from __future__ import annotations

from typing import Any, Dict, List, Set

import botocore

from core.aws import get_client
from core.models import Finding
from core.utils import is_access_denied, safe_call

CRITICAL_PORTS: Set[int] = {22, 3389, 3306, 5432, 27017, 6379}


def _access_denied_finding(account_id: str, region: str, control_id: str, title: str, evidence: Dict[str, Any]) -> Finding:
    return Finding(
        account_id=account_id,
        region=region,
        domain="security",
        control_id=control_id,
        severity="INFO",
        resource="ec2",
        title=title,
        finding="Acesso negado ao executar esta verificação.",
        remediation="Conceda as permissões EC2 necessárias para a role de auditoria.",
        evidence=evidence,
    )


def check_security_groups_open(account_id: str, region: str, session) -> List[Finding]:
    ec2 = get_client(session, "ec2", region=region)
    findings: List[Finding] = []
    paginator = ec2.get_paginator("describe_security_groups")
    try:
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                sg_id = sg["GroupId"]
                sg_name = sg.get("GroupName")
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort")
                    to_port = perm.get("ToPort")
                    if from_port is None or to_port is None:
                        continue
                    ports = set(range(int(from_port), int(to_port) + 1))
                    if not ports.intersection(CRITICAL_PORTS):
                        continue
                    for rng in perm.get("IpRanges", []):
                        cidr = rng.get("CidrIp")
                        if cidr == "0.0.0.0/0":
                            findings.append(
                                Finding(
                                    account_id=account_id,
                                    region=region,
                                    domain="security",
                                    control_id="EC2-001",
                                    severity="HIGH",
                                    resource=sg_id,
                                    title="Security Group aberto para o mundo em porta crítica",
                                    finding=f"Regra de entrada permite {cidr} nas portas {from_port}-{to_port}.",
                                    remediation="Restrinja regras de entrada a CIDRs confiáveis ou outros security groups.",
                                    evidence={
                                        "security_group": sg_id,
                                        "security_group_name": sg_name,
                                        "cidr": cidr,
                                        "from_port": from_port,
                                        "to_port": to_port,
                                    },
                                    resource_type="security-group",
                                    display_name=sg_name,
                                )
                            )
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, region, "EC2-001", "Security Groups não listados", {"error": str(err)})]
        raise
    return findings
