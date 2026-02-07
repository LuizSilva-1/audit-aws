from __future__ import annotations

from typing import Any, Dict, List, Optional

import botocore

from core.aws import get_client
from core.models import Finding
from core.utils import is_access_denied, safe_call, utc_now


def _access_denied_finding(account_id: str, region: str, control_id: str, title: str, evidence: Dict[str, Any]) -> Finding:
    return Finding(
        account_id=account_id,
        region=region,
        domain="finops",
        control_id=control_id,
        severity="INFO",
        resource=control_id,
        title=title,
        finding="Acesso negado ao executar esta verificação.",
        remediation="Conceda as permissões necessárias para a role de auditoria.",
        evidence=evidence,
    )


def _get_tags(tags: Optional[List[Dict[str, str]]]) -> Dict[str, str]:
    if not tags:
        return {}
    return {t.get("Key"): t.get("Value", "") for t in tags}


def check_ec2_required_tags(account_id: str, region: str, session, required_tags: List[str]) -> List[Finding]:
    ec2 = get_client(session, "ec2", region=region)
    findings: List[Finding] = []
    if not required_tags:
        return findings
    paginator = ec2.get_paginator("describe_instances")
    try:
        for page in paginator.paginate():
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    tags = _get_tags(instance.get("Tags"))
                    name_tag = tags.get("Name")
                    missing = [t for t in required_tags if not tags.get(t)]
                    if missing:
                        findings.append(
                            Finding(
                                account_id=account_id,
                                region=region,
                                domain="finops",
                                control_id="FIN-001",
                                severity="MEDIUM",
                                resource=instance.get("InstanceId"),
                        title="Instância EC2 sem tags obrigatórias",
                        finding=f"A instância está sem as tags obrigatórias: {', '.join(missing)}.",
                        remediation="Aplique as tags obrigatórias de alocação de custos na instância.",
                                evidence={
                                    "instance_id": instance.get("InstanceId"),
                                    "missing_tags": missing,
                                    "name_tag": name_tag,
                                },
                                resource_type="ec2-instance",
                                display_name=name_tag,
                            )
                        )
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "FIN-001", "Instâncias EC2 não listadas", {"error": str(err)})]
        raise
    return findings


def check_ebs_required_tags(account_id: str, region: str, session, required_tags: List[str]) -> List[Finding]:
    ec2 = get_client(session, "ec2", region=region)
    findings: List[Finding] = []
    if not required_tags:
        return findings
    paginator = ec2.get_paginator("describe_volumes")
    try:
        for page in paginator.paginate():
            for vol in page.get("Volumes", []):
                tags = _get_tags(vol.get("Tags"))
                missing = [t for t in required_tags if not tags.get(t)]
                if missing:
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=region,
                            domain="finops",
                            control_id="FIN-011",
                            severity="LOW",
                            resource=vol.get("VolumeId"),
                            title="Volume EBS sem tags obrigatórias",
                            finding=f"O volume EBS está sem as tags obrigatórias: {', '.join(missing)}.",
                            remediation="Aplique as tags obrigatórias de alocação de custos no volume EBS.",
                            evidence={"volume_id": vol.get("VolumeId"), "missing_tags": missing},
                            resource_type="ebs-volume",
                            risk_category="cost",
                            confidence="MEDIA",
                        )
                    )
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "FIN-011", "Volumes EBS não listados", {"error": str(err)})]
        raise
    return findings


def check_stopped_instances(account_id: str, region: str, session, older_than_days: int) -> List[Finding]:
    ec2 = get_client(session, "ec2", region=region)
    findings: List[Finding] = []
    paginator = ec2.get_paginator("describe_instances")
    now = utc_now()
    try:
        for page in paginator.paginate(Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]):
            for reservation in page.get("Reservations", []):
                for instance in reservation.get("Instances", []):
                    tags = _get_tags(instance.get("Tags"))
                    name_tag = tags.get("Name")
                    state = instance.get("State", {}).get("Name", "stopped")
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=region,
                            domain="finops",
                            control_id="FIN-002",
                            severity="MEDIUM",
                            resource=instance.get("InstanceId"),
                            title="Instância EC2 parada",
                            finding="Instância EC2 encontra-se em estado STOPPED, gerando custos indiretos com volumes EBS.",
                            remediation="Avalie a necessidade da instância. Caso não seja mais utilizada, considere encerrá-la ou remover os volumes associados.",
                            evidence={
                                "instance_id": instance.get("InstanceId"),
                                "instance_name": name_tag,
                                "state": state,
                            },
                            resource_type="ec2-instance",
                            display_name=name_tag,
                            risk_category="cost",
                            confidence="MEDIA",
                        )
                    )
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "FIN-002", "Instâncias paradas não listadas", {"error": str(err)})]
        raise
    return findings


def check_unattached_volumes(account_id: str, region: str, session) -> List[Finding]:
    ec2 = get_client(session, "ec2", region=region)
    findings: List[Finding] = []
    paginator = ec2.get_paginator("describe_volumes")
    try:
        for page in paginator.paginate(Filters=[{"Name": "status", "Values": ["available"]}]):
            for vol in page.get("Volumes", []):
                findings.append(
                    Finding(
                        account_id=account_id,
                        region=region,
                        domain="finops",
                        control_id="FIN-003",
                        severity="MEDIUM",
                        resource=vol.get("VolumeId"),
                        title="Volume EBS órfão",
                        finding="Volume EBS não está associado a nenhuma instância EC2, gerando custo contínuo.",
                        remediation="Remova o volume EBS caso não seja necessário ou associe-o a uma instância válida.",
                        evidence={
                            "volume_id": vol.get("VolumeId"),
                            "size_gb": vol.get("Size"),
                            "availability_zone": vol.get("AvailabilityZone"),
                        },
                        resource_type="ebs-volume",
                        risk_category="cost",
                        confidence="ALTA",
                    )
                )
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "FIN-003", "Volumes EBS não listados", {"error": str(err)})]
        raise
    return findings


def check_unassociated_eips(account_id: str, region: str, session) -> List[Finding]:
    ec2 = get_client(session, "ec2", region=region)
    findings: List[Finding] = []
    resp, err = safe_call(ec2.describe_addresses)
    if err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "FIN-004", "Elastic IPs não listados", {"error": str(err)})]
        raise err
    for addr in resp.get("Addresses", []):
        if not addr.get("AssociationId"):
            findings.append(
                Finding(
                    account_id=account_id,
                    region=region,
                    domain="finops",
                    control_id="FIN-004",
                    severity="MEDIUM",
                    resource=addr.get("AllocationId", addr.get("PublicIp")),
                    title="Elastic IP não associado",
                    finding="Elastic IP alocado não está associado a nenhuma instância ou recurso.",
                    remediation="Libere o Elastic IP não utilizado para evitar custos desnecessários.",
                    evidence={"public_ip": addr.get("PublicIp"), "allocation_id": addr.get("AllocationId")},
                    resource_type="elastic-ip",
                    risk_category="cost",
                    confidence="ALTA",
                )
            )
    return findings


def check_ebs_gp2_volumes(account_id: str, region: str, session) -> List[Finding]:
    ec2 = get_client(session, "ec2", region=region)
    findings: List[Finding] = []
    paginator = ec2.get_paginator("describe_volumes")
    try:
        for page in paginator.paginate():
            for vol in page.get("Volumes", []):
                if vol.get("VolumeType") == "gp2":
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=region,
                            domain="finops",
                            control_id="FIN-009",
                            severity="LOW",
                            resource=vol.get("VolumeId"),
                            title="Volume EBS usando gp2",
                            finding="Volume EBS está usando gp2, que pode ser mais caro que gp3.",
                            remediation="Avalie migração para gp3 para reduzir custos sem perda de performance.",
                            evidence={
                                "volume_id": vol.get("VolumeId"),
                                "size_gb": vol.get("Size"),
                                "volume_type": vol.get("VolumeType"),
                            },
                            resource_type="ebs-volume",
                            risk_category="cost",
                            confidence="MEDIA",
                        )
                    )
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "FIN-009", "Volumes EBS não listados", {"error": str(err)})]
        raise
    return findings


def check_old_snapshots(account_id: str, region: str, session) -> List[Finding]:
    ec2 = get_client(session, "ec2", region=region)
    findings: List[Finding] = []
    paginator = ec2.get_paginator("describe_snapshots")
    try:
        for page in paginator.paginate(OwnerIds=["self"]):
            for snap in page.get("Snapshots", []):
                start_time = snap.get("StartTime")
                if start_time is None:
                    continue
                age_days = (utc_now() - start_time).days
                if age_days >= 180:
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=region,
                            domain="finops",
                            control_id="FIN-010",
                            severity="LOW",
                            resource=snap.get("SnapshotId"),
                            title="Snapshot EBS antigo",
                            finding="Snapshot EBS com idade acima de 180 dias pode gerar custo desnecessário.",
                            remediation="Revise a necessidade do snapshot e remova se não houver exigência.",
                            evidence={
                                "snapshot_id": snap.get("SnapshotId"),
                                "start_time": start_time.isoformat(),
                                "age_days": age_days,
                            },
                            resource_type="ebs-snapshot",
                            risk_category="cost",
                            confidence="MEDIA",
                        )
                    )
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "FIN-010", "Snapshots EBS não listados", {"error": str(err)})]
        raise
    return findings


def check_orphaned_snapshots(account_id: str, region: str, session) -> List[Finding]:
    ec2 = get_client(session, "ec2", region=region)
    findings: List[Finding] = []
    volume_ids = set()
    try:
        paginator = ec2.get_paginator("describe_volumes")
        for page in paginator.paginate():
            for vol in page.get("Volumes", []):
                volume_ids.add(vol.get("VolumeId"))
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "FIN-006", "Volumes EBS não listados", {"error": str(err)})]
        raise

    try:
        paginator = ec2.get_paginator("describe_snapshots")
        for page in paginator.paginate(OwnerIds=["self"]):
            for snap in page.get("Snapshots", []):
                vol_id = snap.get("VolumeId")
                if vol_id and vol_id not in volume_ids:
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=region,
                            domain="finops",
                            control_id="FIN-006",
                            severity="MEDIUM",
                            resource=snap.get("SnapshotId"),
                            title="Snapshot EBS órfão",
                            finding="Snapshot EBS não está associado a um volume existente.",
                            remediation="Remova snapshots órfãos se não forem necessários.",
                            evidence={
                                "snapshot_id": snap.get("SnapshotId"),
                                "volume_id": vol_id,
                                "size_gb": snap.get("VolumeSize"),
                            },
                            resource_type="ebs-snapshot",
                            risk_category="cost",
                            confidence="MEDIA",
                        )
                    )
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "FIN-006", "Snapshots EBS não listados", {"error": str(err)})]
        raise
    return findings


def check_elb_no_targets(account_id: str, region: str, session) -> List[Finding]:
    elbv2 = get_client(session, "elbv2", region=region)
    findings: List[Finding] = []
    paginator = elbv2.get_paginator("describe_load_balancers")
    try:
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                lb_arn = lb.get("LoadBalancerArn")
                tg_resp, err = safe_call(elbv2.describe_target_groups, LoadBalancerArn=lb_arn)
                if err:
                    if is_access_denied(err):
                        findings.append(_access_denied_finding(account_id, region, "FIN-007", "Target groups não listados", {"error": str(err), "load_balancer": lb_arn}))
                        continue
                    raise err
                tgs = tg_resp.get("TargetGroups", [])
                total_targets = 0
                for tg in tgs:
                    tg_arn = tg.get("TargetGroupArn")
                    th, err = safe_call(elbv2.describe_target_health, TargetGroupArn=tg_arn)
                    if err:
                        if is_access_denied(err):
                            findings.append(_access_denied_finding(account_id, region, "FIN-007", "Target health não verificado", {"error": str(err), "target_group": tg_arn}))
                            continue
                        raise err
                    total_targets += len(th.get("TargetHealthDescriptions", []))
                if not tgs or total_targets == 0:
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=region,
                            domain="finops",
                            control_id="FIN-007",
                            severity="MEDIUM",
                            resource=lb_arn,
                            title="Load balancer sem targets",
                            finding="Load balancer não possui targets registrados.",
                            remediation="Remova o load balancer se não estiver em uso ou registre targets válidos.",
                            evidence={
                                "load_balancer_arn": lb_arn,
                                "target_group_count": len(tgs),
                                "total_targets": total_targets,
                            },
                            resource_type="load-balancer",
                            risk_category="cost",
                            confidence="MEDIA",
                        )
                    )
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "FIN-007", "Load balancers não listados", {"error": str(err)})]
        raise
    return findings
