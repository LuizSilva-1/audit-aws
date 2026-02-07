from __future__ import annotations

from typing import Any, Dict, List
import time

import botocore

from core.aws import get_client
from core.models import Finding
from core.utils import is_access_denied, safe_call


def _access_denied_finding(account_id: str, control_id: str, title: str, evidence: Dict[str, Any]) -> Finding:
    return Finding(
        account_id=account_id,
        region=None,
        domain="security" if control_id.startswith("S3-") else "finops",
        control_id=control_id,
        severity="INFO",
        resource="s3",
        title=title,
        finding="Acesso negado ao executar esta verificação.",
        remediation="Conceda as permissões S3 necessárias para a role de auditoria.",
        evidence=evidence,
    )


def check_s3_public(account_id: str, session) -> List[Finding]:
    s3 = get_client(session, "s3")
    findings: List[Finding] = []
    buckets_resp, err = safe_call(s3.list_buckets)
    if err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, "S3-001", "Buckets S3 não listados", {"error": str(err)})]
        raise err
    for bucket in buckets_resp.get("Buckets", []):
        name = bucket["Name"]
        status, err = safe_call(s3.get_bucket_policy_status, Bucket=name)
        if err and not is_access_denied(err):
            if isinstance(err, botocore.exceptions.ClientError):
                code = err.response.get("Error", {}).get("Code", "")
                if code == "NoSuchBucketPolicy":
                    status = None
                    err = None
            if err:
                raise err
        if err and is_access_denied(err):
            findings.append(_access_denied_finding(account_id, "S3-001", f"Status da política do bucket não lido {name}", {"error": str(err), "bucket": name}))
            continue
        is_public = status.get("PolicyStatus", {}).get("IsPublic") if status else False
        if is_public:
            findings.append(
                Finding(
                    account_id=account_id,
                    region=None,
                    domain="security",
                    control_id="S3-001",
                    severity="HIGH",
                    resource=name,
                    title="Política do bucket S3 permite acesso público",
                    finding="A política do bucket é pública conforme o status da política.",
                    remediation="Remova o acesso público e restrinja a política do bucket.",
                    evidence={"bucket": name, "is_public": True},
                )
            )
            continue
        pab, err = safe_call(s3.get_public_access_block, Bucket=name)
        if err:
            if is_access_denied(err):
                findings.append(_access_denied_finding(account_id, "S3-001", f"Bloqueio de acesso público não lido {name}", {"error": str(err), "bucket": name}))
                continue
            if isinstance(err, botocore.exceptions.ClientError):
                code = err.response.get("Error", {}).get("Code", "")
                if code == "NoSuchPublicAccessBlockConfiguration":
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=None,
                            domain="security",
                            control_id="S3-001",
                            severity="MEDIUM",
                            resource=name,
                            title="Bucket S3 sem bloqueio de acesso público",
                            finding="Nenhuma configuração de PublicAccessBlock encontrada.",
                            remediation="Habilite o bloqueio de acesso público do S3 para o bucket.",
                            evidence={"bucket": name},
                        )
                    )
                    continue
            raise err
        config = pab.get("PublicAccessBlockConfiguration", {}) if pab else {}
        if not all(config.get(k) for k in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]):
            findings.append(
                Finding(
                    account_id=account_id,
                    region=None,
                    domain="security",
                    control_id="S3-001",
                    severity="MEDIUM",
                    resource=name,
                    title="Bloqueio de acesso público do bucket S3 incompleto",
                    finding="A configuração de PublicAccessBlock está faltando uma ou mais opções.",
                    remediation="Habilite todas as opções de bloqueio de acesso público do S3.",
                    evidence={"bucket": name, "public_access_block": config},
                )
            )
    return findings


def check_s3_lifecycle(account_id: str, session) -> List[Finding]:
    s3 = get_client(session, "s3")
    findings: List[Finding] = []
    buckets_resp, err = safe_call(s3.list_buckets)
    if err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, "S3-002", "Buckets S3 não listados", {"error": str(err)})]
        raise err
    for bucket in buckets_resp.get("Buckets", []):
        name = bucket["Name"]
        lc, err = safe_call(s3.get_bucket_lifecycle_configuration, Bucket=name)
        if err:
            if is_access_denied(err):
                findings.append(_access_denied_finding(account_id, "S3-002", f"Ciclo de vida não lido {name}", {"error": str(err), "bucket": name}))
                continue
            if isinstance(err, botocore.exceptions.ClientError):
                code = err.response.get("Error", {}).get("Code", "")
                if code == "NoSuchLifecycleConfiguration":
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=None,
                            domain="finops",
                            control_id="S3-002",
                            severity="LOW",
                            resource=name,
                            title="Bucket S3 sem configuração de ciclo de vida",
                            finding="O bucket não possui configuração de ciclo de vida.",
                            remediation="Adicione políticas de ciclo de vida para gerenciar custos de armazenamento.",
                            evidence={"bucket": name},
                        )
                    )
                    continue
            raise err
        if lc and not lc.get("Rules"):
            findings.append(
                Finding(
                    account_id=account_id,
                    region=None,
                    domain="finops",
                    control_id="S3-002",
                    severity="LOW",
                    resource=name,
                    title="Bucket S3 sem configuração de ciclo de vida",
                    finding="O bucket não possui regras de ciclo de vida.",
                    remediation="Adicione políticas de ciclo de vida para gerenciar custos de armazenamento.",
                    evidence={"bucket": name},
                )
            )
    return findings


def check_s3_versioning(account_id: str, session) -> List[Finding]:
    s3 = get_client(session, "s3")
    findings: List[Finding] = []
    buckets_resp, err = safe_call(s3.list_buckets)
    if err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, "S3-003", "Buckets S3 não listados", {"error": str(err)})]
        raise err
    for bucket in buckets_resp.get("Buckets", []):
        name = bucket["Name"]
        ver, err = safe_call(s3.get_bucket_versioning, Bucket=name)
        if err:
            if is_access_denied(err):
                findings.append(_access_denied_finding(account_id, "S3-003", f"Versionamento não verificado {name}", {"error": str(err), "bucket": name}))
                continue
            raise err
        status = (ver or {}).get("Status")
        if status != "Enabled":
            findings.append(
                Finding(
                    account_id=account_id,
                    region=None,
                    domain="security",
                    control_id="S3-003",
                    severity="MEDIUM",
                    resource=name,
                    title="Versionamento do S3 desabilitado",
                    finding="O bucket S3 não possui versionamento habilitado.",
                    remediation="Habilite o versionamento para reduzir risco de perda de dados acidental.",
                    evidence={"bucket_name": name, "status": status or "NotEnabled"},
                    resource_type="s3-bucket",
                    risk_category="governance",
                    confidence="ALTA",
                )
            )
    return findings


def check_s3_standard_objects(account_id: str, session) -> List[Finding]:
    s3 = get_client(session, "s3")
    findings: List[Finding] = []
    buckets_resp, err = safe_call(s3.list_buckets)
    if err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, "FIN-005", "Buckets S3 não listados", {"error": str(err)})]
        raise err
    for bucket in buckets_resp.get("Buckets", []):
        name = bucket["Name"]
        lc, err = safe_call(s3.get_bucket_lifecycle_configuration, Bucket=name)
        if err:
            if is_access_denied(err):
                findings.append(_access_denied_finding(account_id, "FIN-005", f"Ciclo de vida não lido {name}", {"error": str(err), "bucket": name}))
                continue
            if isinstance(err, botocore.exceptions.ClientError):
                code = err.response.get("Error", {}).get("Code", "")
                if code == "NoSuchLifecycleConfiguration":
                    lc = None
                else:
                    raise err
            else:
                raise err
        if lc and lc.get("Rules"):
            continue

        object_count_standard = 0
        paginacao_interrompida = False
        standard_detectado = False
        objetos_verificados = 0
        inicio = time.monotonic()
        limite_segundos = 10
        paginator = s3.get_paginator("list_objects_v2")
        try:
            for page in paginator.paginate(Bucket=name):
                if time.monotonic() - inicio > limite_segundos:
                    paginacao_interrompida = True
                    break
                for obj in page.get("Contents", []):
                    objetos_verificados += 1
                    storage_class = obj.get("StorageClass") or "STANDARD"
                    if storage_class == "STANDARD":
                        object_count_standard = 1
                        standard_detectado = True
                        break
                if standard_detectado:
                    break
        except botocore.exceptions.ClientError as e:
            if is_access_denied(e):
                findings.append(_access_denied_finding(account_id, "FIN-005", f"Objetos não listados {name}", {"error": str(e), "bucket": name}))
                continue
            raise

        if standard_detectado:
            findings.append(
                Finding(
                    account_id=account_id,
                    region=None,
                    domain="finops",
                    control_id="FIN-005",
                    severity="LOW",
                    resource=name,
                    title="Objetos em STANDARD sem otimização",
                    finding="Bucket S3 possui objetos armazenados na classe STANDARD sem política de otimização de armazenamento.",
                    remediation="Avalie a criação de políticas de lifecycle para transicionar objetos para classes mais econômicas como IA ou Glacier.",
                    evidence={
                        "bucket_name": name,
                        "object_count_standard": object_count_standard,
                        "standard_detectado": standard_detectado,
                        "objetos_verificados": objetos_verificados,
                        "paginacao_interrompida_timeout": paginacao_interrompida,
                    },
                    resource_type="s3-bucket",
                    risk_category="cost",
                    confidence="MEDIA",
                )
            )
    return findings


def check_s3_default_encryption(account_id: str, session) -> List[Finding]:
    s3 = get_client(session, "s3")
    findings: List[Finding] = []
    buckets_resp, err = safe_call(s3.list_buckets)
    if err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, "S3-004", "Buckets S3 não listados", {"error": str(err)})]
        raise err
    for bucket in buckets_resp.get("Buckets", []):
        name = bucket["Name"]
        enc, err = safe_call(s3.get_bucket_encryption, Bucket=name)
        if err:
            if is_access_denied(err):
                findings.append(_access_denied_finding(account_id, "S3-004", f"Criptografia não verificada {name}", {"error": str(err), "bucket": name}))
                continue
            if isinstance(err, botocore.exceptions.ClientError):
                code = err.response.get("Error", {}).get("Code", "")
                if code == "ServerSideEncryptionConfigurationNotFoundError":
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=None,
                            domain="security",
                            control_id="S3-004",
                            severity="MEDIUM",
                            resource=name,
                            title="Criptografia padrão do S3 desabilitada",
                            finding="O bucket S3 não possui criptografia padrão habilitada.",
                            remediation="Habilite criptografia padrão (SSE-S3 ou SSE-KMS) no bucket.",
                            evidence={"bucket_name": name},
                            resource_type="s3-bucket",
                            risk_category="encryption",
                            confidence="ALTA",
                        )
                    )
                    continue
            raise err
    return findings
