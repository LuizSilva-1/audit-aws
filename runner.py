from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
from typing import Any, Dict, List

import yaml

from collectors.ec2_checks import check_security_groups_open
from collectors.finops_checks import (
    check_ec2_required_tags,
    check_stopped_instances,
    check_unassociated_eips,
    check_unattached_volumes,
    check_orphaned_snapshots,
    check_elb_no_targets,
    check_ebs_gp2_volumes,
    check_old_snapshots,
    check_ebs_required_tags,
)
from collectors.iam_checks import run_iam_checks
from collectors.s3_checks import (
    check_s3_lifecycle,
    check_s3_public,
    check_s3_standard_objects,
    check_s3_versioning,
    check_s3_default_encryption,
)
from collectors.security_checks import (
    check_cloudtrail,
    check_ebs_encryption_default,
    check_rds_encryption,
    check_rds_backup_retention,
    check_aws_config_enabled,
    check_enabled_regions,
)
from core.aws import AwsConfig, session_for_target
from core.exceptions import apply_exceptions, load_exceptions
from core.logger import setup_logger
from core.models import Finding
from core.reporting import compare_findings, console_summary, enrich_findings, gerar_diff_markdown, gerar_relatorio_markdown, gerar_relatorio_html
from core.scoring import compute_score, top_penalty_controls
from core.utils import utc_now


CONFIG_FILE = "config.yaml"
EXCEPTIONS_FILE = "exceptions.yaml"


def load_config(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    with open(path, "r", encoding="utf-8") as fh:
        return yaml.safe_load(fh) or {}


def findings_to_csv(findings: List[Dict[str, Any]], csv_path: Path) -> None:
    if not findings:
        return
    fields = list(findings[0].keys())
    with open(csv_path, "w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(findings)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="AWS Audit MVP - Auditoria inicial")
    parser.add_argument("--compare", help="Arquivo JSON de achados anterior para comparação", default=None)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    logger = setup_logger()
    try:
        config = load_config(CONFIG_FILE)
    except FileNotFoundError:
        logger.error("Arquivo config.yaml ausente. Copie config.example.yaml para config.yaml e personalize.")
        return

    aws_cfg = AwsConfig(
        mode=config.get("mode", "profile"),
        profile=config.get("profile"),
        role_arns=config.get("assume_role", {}).get("role_arns", []) or [],
        external_id=config.get("assume_role", {}).get("external_id"),
        regions=config.get("regions", []) or [],
    )

    if not aws_cfg.regions:
        logger.error("Nenhuma região configurada. Defina regiões em config.yaml.")
        return

    outputs_dir = Path("outputs")
    outputs_dir.mkdir(parents=True, exist_ok=True)
    ts = utc_now().strftime("%Y%m%d-%H%M%S")
    json_path = outputs_dir / f"findings-{ts}.json"
    csv_path = outputs_dir / f"findings-{ts}.csv"

    all_findings: List[Finding] = []

    for account_id, session in session_for_target(aws_cfg):
        logger.info("Iniciando auditoria para a conta %s", account_id)
        logger.info("Executando verificações de IAM")
        all_findings.extend(run_iam_checks(account_id, session))

        all_findings.extend(check_enabled_regions(account_id, session, aws_cfg.regions))

        logger.info("Executando verificações de S3")
        all_findings.extend(check_s3_public(account_id, session))
        all_findings.extend(check_s3_lifecycle(account_id, session))
        all_findings.extend(check_s3_standard_objects(account_id, session))
        all_findings.extend(check_s3_versioning(account_id, session))
        all_findings.extend(check_s3_default_encryption(account_id, session))

        for region in aws_cfg.regions:
            logger.info("Executando verificações regionais em %s", region)
            all_findings.extend(check_security_groups_open(account_id, region, session))
            all_findings.extend(check_cloudtrail(account_id, region, session))
            all_findings.extend(check_ebs_encryption_default(account_id, region, session))
            all_findings.extend(check_rds_encryption(account_id, region, session))
            all_findings.extend(check_rds_backup_retention(account_id, region, session))
            all_findings.extend(check_aws_config_enabled(account_id, region, session))

            tag_policy = config.get("tag_policy", {}) or {}
            required_tags = tag_policy.get("required_tags", []) or []
            stopped_days = int(tag_policy.get("stopped_instance_days", 7))
            all_findings.extend(check_ec2_required_tags(account_id, region, session, required_tags))
            all_findings.extend(check_ebs_required_tags(account_id, region, session, required_tags))
            all_findings.extend(check_stopped_instances(account_id, region, session, stopped_days))
            all_findings.extend(check_unattached_volumes(account_id, region, session))
            all_findings.extend(check_unassociated_eips(account_id, region, session))
            all_findings.extend(check_orphaned_snapshots(account_id, region, session))
            all_findings.extend(check_elb_no_targets(account_id, region, session))
            all_findings.extend(check_ebs_gp2_volumes(account_id, region, session))
            all_findings.extend(check_old_snapshots(account_id, region, session))

    all_findings = enrich_findings(all_findings)

    exceptions = load_exceptions(EXCEPTIONS_FILE)
    all_findings = apply_exceptions(all_findings, exceptions)

    my_ip_cidr = config.get("my_ip_cidr")
    if my_ip_cidr:
        for f in all_findings:
            if f.control_id == "EC2-001":
                f.remediation = f.remediation + f" Sugestão: restrinja SSH/RDP ao seu IP {my_ip_cidr}."

    findings_dicts = [f.to_dict() for f in all_findings]
    with open(json_path, "w", encoding="utf-8") as fh:
        json.dump(findings_dicts, fh, indent=2, ensure_ascii=False)

    findings_to_csv(findings_dicts, csv_path)

    tag_policy = config.get("tag_policy", {}) or {}
    required_tags = tag_policy.get("required_tags", []) or []
    score_obj = compute_score(all_findings)
    report_md = gerar_relatorio_markdown(all_findings, ts, required_tags, score_obj)
    report_path = outputs_dir / f"report-{ts}.md"
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write(report_md)
    report_html = gerar_relatorio_html(all_findings, ts, required_tags, score_obj)
    report_html_path = outputs_dir / f"report-{ts}.html"
    with open(report_html_path, "w", encoding="utf-8") as fh:
        fh.write(report_html)

    logger.info("%s", console_summary(all_findings))
    logger.info("Score geral: %s", score_obj["overall"])
    logger.info("Score por domínio: %s", score_obj["domains"])
    principais = top_penalty_controls(score_obj, all_findings, limit=3)
    logger.info("Principais motivos de queda do score:")
    for item in principais:
        logger.info("- %s: %s (ocorrências: %s)", item["control_id"], item["title"], item["count"])
    logger.info("Achados gravados em %s", json_path)
    if findings_dicts:
        logger.info("CSV gravado em %s", csv_path)
    logger.info("Relatório executivo gravado em %s", report_path)
    logger.info("Relatório HTML gravado em %s", report_html_path)

    results_path = outputs_dir / f"results-{ts}.json"
    with open(results_path, "w", encoding="utf-8") as fh:
        json.dump({"metadata": {"score": score_obj}, "findings": findings_dicts}, fh, indent=2, ensure_ascii=False)
    logger.info("Resultados com score gravados em %s", results_path)

    if args.compare:
        try:
            with open(args.compare, "r", encoding="utf-8") as fh:
                old_findings = json.load(fh)
            diff = compare_findings(all_findings, old_findings)
            diff_md = gerar_diff_markdown(ts, diff)
            diff_path = outputs_dir / f"diff-{ts}.md"
            with open(diff_path, "w", encoding="utf-8") as fh:
                fh.write(diff_md)
            logger.info("Comparativo gravado em %s", diff_path)
        except FileNotFoundError:
            logger.error("Arquivo de comparação não encontrado: %s", args.compare)


if __name__ == "__main__":
    main()
