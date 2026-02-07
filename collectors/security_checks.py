from __future__ import annotations

from typing import Any, Dict, List

import botocore

from core.aws import get_client
from core.models import Finding
from core.utils import is_access_denied, safe_call


def _access_denied_finding(account_id: str, region: str, control_id: str, title: str, evidence: Dict[str, Any]) -> Finding:
    return Finding(
        account_id=account_id,
        region=region,
        domain="security",
        control_id=control_id,
        severity="INFO",
        resource=control_id,
        title=title,
        finding="Acesso negado ao executar esta verificação.",
        remediation="Conceda as permissões necessárias para a role de auditoria.",
        evidence=evidence,
    )


def check_cloudtrail(account_id: str, region: str, session) -> List[Finding]:
    ct = get_client(session, "cloudtrail", region=region)
    findings: List[Finding] = []
    trails, err = safe_call(ct.describe_trails, includeShadowTrails=False)
    if err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "LOG-001", "CloudTrail não listado", {"error": str(err)})]
        raise err
    trail_list = trails.get("trailList", []) if trails else []
    if not trail_list:
        findings.append(
            Finding(
                account_id=account_id,
                region=region,
                domain="security",
                control_id="LOG-001",
                severity="MEDIUM",
                resource="cloudtrail",
                title="Nenhuma trilha do CloudTrail encontrada",
                finding="Nenhuma trilha do CloudTrail está configurada nesta região.",
                remediation="Habilite o CloudTrail com logging multi-região.",
                evidence={"region": region},
            )
        )
        return findings
    for trail in trail_list:
        name = trail.get("Name", "unknown")
        is_multi = trail.get("IsMultiRegionTrail", False)
        log_validation = trail.get("LogFileValidationEnabled", False)
        status, err = safe_call(ct.get_trail_status, Name=name)
        if err:
            if is_access_denied(err):
                findings.append(_access_denied_finding(account_id, region, "LOG-001", f"Status da trilha não lido {name}", {"error": str(err), "trail": name}))
                continue
            raise err
        if not status.get("IsLogging", False) or not is_multi:
            findings.append(
                Finding(
                    account_id=account_id,
                    region=region,
                    domain="security",
                    control_id="LOG-001",
                    severity="MEDIUM",
                    resource=name,
                    title="CloudTrail não está totalmente habilitado",
                    finding="A trilha não está registrando ou não é multi-região.",
                    remediation="Garanta que o CloudTrail esteja habilitado e configurado como multi-região.",
                    evidence={"trail": name, "is_logging": status.get("IsLogging"), "is_multi_region": is_multi},
                )
            )
        if not log_validation:
            findings.append(
                Finding(
                    account_id=account_id,
                    region=region,
                    domain="governance",
                    control_id="GOV-002",
                    severity="LOW",
                    resource=name,
                    title="Validação de logs do CloudTrail desabilitada",
                    finding="A validação de integridade de logs do CloudTrail não está habilitada.",
                    remediation="Habilite Log File Validation no CloudTrail para garantir integridade dos logs.",
                    evidence={"trail": name, "log_validation_enabled": log_validation},
                    resource_type="cloudtrail",
                    risk_category="governance",
                    confidence="ALTA",
                )
            )
    return findings


def check_ebs_encryption_default(account_id: str, region: str, session) -> List[Finding]:
    ec2 = get_client(session, "ec2", region=region)
    findings: List[Finding] = []
    resp, err = safe_call(ec2.get_ebs_encryption_by_default)
    if err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "ENC-001", "Criptografia padrão do EBS não verificada", {"error": str(err)})]
        raise err
    if not resp.get("EbsEncryptionByDefault", False):
        findings.append(
            Finding(
                account_id=account_id,
                region=region,
                domain="security",
                control_id="ENC-001",
                severity="MEDIUM",
                resource="ebs-default-encryption",
                title="Criptografia padrão do EBS está desabilitada",
                finding="Volumes EBS não são criptografados por padrão nesta região.",
                remediation="Habilite a criptografia padrão do EBS.",
                evidence={"region": region},
            )
        )
    return findings


def check_rds_encryption(account_id: str, region: str, session) -> List[Finding]:
    rds = get_client(session, "rds", region=region)
    findings: List[Finding] = []
    paginator = rds.get_paginator("describe_db_instances")
    try:
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                if not db.get("StorageEncrypted", False):
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=region,
                            domain="security",
                            control_id="RDS-001",
                            severity="MEDIUM",
                            resource=db.get("DBInstanceArn", db.get("DBInstanceIdentifier")),
                    title="Instância RDS não criptografada em repouso",
                    finding="O armazenamento do RDS não está criptografado.",
                    remediation="Habilite criptografia em repouso para a instância RDS.",
                            evidence={"db_instance": db.get("DBInstanceIdentifier")},
                        )
                    )
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "RDS-001", "Instâncias RDS não listadas", {"error": str(err)})]
        raise
    return findings


def check_rds_backup_retention(account_id: str, region: str, session) -> List[Finding]:
    rds = get_client(session, "rds", region=region)
    findings: List[Finding] = []
    paginator = rds.get_paginator("describe_db_instances")
    try:
        for page in paginator.paginate():
            for db in page.get("DBInstances", []):
                retention = db.get("BackupRetentionPeriod")
                if retention is None or retention < 7:
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=region,
                            domain="governance",
                            control_id="GOV-001",
                            severity="MEDIUM",
                            resource=db.get("DBInstanceArn", db.get("DBInstanceIdentifier")),
                            title="Retenção de backup do RDS baixa",
                            finding="A retenção de backup do RDS está abaixo do recomendado.",
                            remediation="Aumente a retenção de backups para pelo menos 7 dias.",
                            evidence={"db_instance": db.get("DBInstanceIdentifier"), "retention_days": retention},
                            resource_type="rds-instance",
                            risk_category="governance",
                            confidence="MEDIA",
                        )
                    )
                elif retention > 7:
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=region,
                            domain="finops",
                            control_id="FIN-008",
                            severity="LOW",
                            resource=db.get("DBInstanceArn", db.get("DBInstanceIdentifier")),
                            title="Retenção de backup do RDS acima do necessário",
                            finding="A retenção de backup do RDS está acima de 7 dias, podendo gerar custos adicionais.",
                            remediation="Avalie a necessidade de retenção estendida e reduza se não houver exigência técnica ou regulatória.",
                            evidence={"db_instance": db.get("DBInstanceIdentifier"), "retention_days": retention},
                            resource_type="rds-instance",
                            risk_category="cost",
                            confidence="MEDIA",
                        )
                    )
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "GOV-001", "Retenção de backup do RDS não verificada", {"error": str(err)})]
        raise
    return findings


def check_aws_config_enabled(account_id: str, region: str, session) -> List[Finding]:
    config = get_client(session, "config", region=region)
    findings: List[Finding] = []
    resp, err = safe_call(config.describe_configuration_recorders)
    if err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "GOV-003", "AWS Config não verificado", {"error": str(err)})]
        raise err
    recorders = resp.get("ConfigurationRecorders", [])
    if not recorders:
        findings.append(
            Finding(
                account_id=account_id,
                region=region,
                domain="governance",
                control_id="GOV-003",
                severity="LOW",
                resource="aws-config",
                title="AWS Config desabilitado",
                finding="Não há configuration recorders configurados nesta região.",
                remediation="Habilite AWS Config para rastrear mudanças de configuração.",
                evidence={"region": region, "recorders": 0},
                resource_type="aws-config",
                risk_category="governance",
                confidence="ALTA",
            )
        )
        return findings

    status, err = safe_call(config.describe_configuration_recorder_status)
    if err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "GOV-003", "Status do AWS Config não verificado", {"error": str(err)})]
        raise err
    statuses = status.get("ConfigurationRecordersStatus", [])
    if not any(s.get("recording") for s in statuses):
        findings.append(
            Finding(
                account_id=account_id,
                region=region,
                domain="governance",
                control_id="GOV-003",
                severity="LOW",
                resource="aws-config",
                title="AWS Config não está gravando",
                finding="AWS Config está configurado, mas não está gravando nesta região.",
                remediation="Ative a gravação do AWS Config para a região.",
                evidence={"region": region, "recording": False},
                resource_type="aws-config",
                risk_category="governance",
                confidence="MEDIA",
            )
        )
    return findings


def check_enabled_regions(account_id: str, session, allowed_regions: List[str]) -> List[Finding]:
    regiao_base = allowed_regions[0] if allowed_regions else "us-east-1"
    ec2 = get_client(session, "ec2", region=regiao_base)
    findings: List[Finding] = []
    resp, err = safe_call(ec2.describe_regions, AllRegions=True)
    if err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, None, "GOV-004", "Regiões não verificadas", {"error": str(err)})]
        raise err
    allowed = set(allowed_regions or [])
    for reg in resp.get("Regions", []):
        name = reg.get("RegionName")
        status = reg.get("OptInStatus")
        habilitada = status in {"opted-in", "opt-in-not-required"}
        if habilitada and name not in allowed:
            findings.append(
                Finding(
                    account_id=account_id,
                    region=name,
                    domain="governance",
                    control_id="GOV-004",
                    severity="LOW",
                    resource=name,
                    title="Região habilitada fora da lista permitida",
                    finding="A região está habilitada na conta, mas não faz parte da lista de regiões permitidas.",
                    remediation="Considere restringir o uso da região via SCP ou políticas internas.",
                    evidence={"region": name, "opt_in_status": status, "allowed_regions": list(allowed)},
                    resource_type="aws-region",
                    risk_category="governance",
                    confidence="ALTA",
                )
            )
    return findings
