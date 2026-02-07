from __future__ import annotations

import json
from datetime import timedelta
from typing import Any, Dict, List

import botocore

from core.aws import get_client
from core.models import Finding
from core.utils import ensure_tz, is_access_denied, safe_call, utc_now


def _access_denied_finding(account_id: str, control_id: str, title: str, evidence: Dict[str, Any]) -> Finding:
    return Finding(
        account_id=account_id,
        region=None,
        domain="iam",
        control_id=control_id,
        severity="INFO",
        resource="iam",
        title=title,
        finding="Acesso negado ao executar esta verificação.",
        remediation="Conceda as permissões IAM necessárias para a role de auditoria.",
        evidence=evidence,
    )


def check_root_mfa(account_id: str, iam_client) -> List[Finding]:
    findings: List[Finding] = []
    resp, err = safe_call(iam_client.get_account_summary)
    if err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, "IAM-001", "Status do MFA da conta root não verificado", {"error": str(err)})]
        raise err
    mfa_enabled = resp.get("SummaryMap", {}).get("AccountMFAEnabled", 0)
    if int(mfa_enabled) == 0:
        findings.append(
            Finding(
                account_id=account_id,
                region=None,
                domain="iam",
                control_id="IAM-001",
                severity="CRITICAL",
                resource="root",
                title="MFA da conta root não habilitado",
                finding="A conta root não possui MFA habilitado.",
                remediation="Habilite MFA na conta root e armazene as credenciais com segurança.",
                evidence={"AccountMFAEnabled": mfa_enabled},
            )
        )
    return findings


def check_users_exist(account_id: str, iam_client) -> List[Finding]:
    findings: List[Finding] = []
    users: List[Dict[str, Any]] = []
    paginator = iam_client.get_paginator("list_users")
    try:
        for page in paginator.paginate():
            users.extend(page.get("Users", []))
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, "IAM-002", "Usuários IAM não listados", {"error": str(err)})]
        raise
    if users:
        findings.append(
            Finding(
                account_id=account_id,
                region=None,
                domain="iam",
                control_id="IAM-002",
                severity="MEDIUM",
                resource="iam-users",
                title="Existem usuários IAM na conta",
                finding=f"Foram encontrados {len(users)} usuários IAM na conta.",
                remediation="Garanta que os usuários IAM sejam necessários e tenham MFA; prefira acesso federado.",
                evidence={"user_count": len(users)},
            )
        )
    return findings


def check_users_without_mfa(account_id: str, iam_client) -> List[Finding]:
    findings: List[Finding] = []
    paginator = iam_client.get_paginator("list_users")
    try:
        for page in paginator.paginate():
            for user in page.get("Users", []):
                user_name = user["UserName"]
                mfa, err = safe_call(iam_client.list_mfa_devices, UserName=user_name)
                if err:
                    if is_access_denied(err):
                        findings.append(
                            _access_denied_finding(
                                account_id,
                                "IAM-008",
                                f"MFA não verificado para usuário {user_name}",
                                {"error": str(err), "user": user_name},
                            )
                        )
                        continue
                    raise err
                password_last_used = user.get("PasswordLastUsed")
                tem_console = password_last_used is not None
                if not mfa.get("MFADevices") and tem_console:
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=None,
                            domain="iam",
                            control_id="IAM-008",
                            severity="MEDIUM",
                            resource=user.get("Arn", user_name),
                            title="Usuário IAM com console sem MFA",
                            finding="Usuário IAM com acesso ao console não possui MFA habilitado.",
                            remediation="Habilite MFA para o usuário ou migre para acesso federado.",
                            evidence={"user": user_name, "mfa_devices": 0, "password_last_used": str(password_last_used)},
                            resource_type="iam-user",
                            risk_category="identity",
                            confidence="ALTA",
                        )
                    )
                elif not mfa.get("MFADevices") and not tem_console:
                    keys_resp, err = safe_call(iam_client.list_access_keys, UserName=user_name)
                    if err:
                        if is_access_denied(err):
                            findings.append(
                                _access_denied_finding(
                                    account_id,
                                    "IAM-008",
                                    f"Chaves de acesso não verificadas para usuário {user_name}",
                                    {"error": str(err), "user": user_name},
                                )
                            )
                            continue
                        raise err
                    if not keys_resp.get("AccessKeyMetadata"):
                        continue
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=None,
                            domain="iam",
                            control_id="IAM-008",
                            severity="INFO",
                            resource=user.get("Arn", user_name),
                            title="Usuário IAM sem uso de console",
                            finding="Usuário IAM não utiliza console. Prefira acesso via roles e credenciais temporárias.",
                            remediation="Considere migrar o acesso para roles assumíveis e remover credenciais permanentes.",
                            evidence={"user": user_name, "mfa_devices": 0, "password_last_used": None},
                            resource_type="iam-user",
                            risk_category="identity",
                            confidence="MEDIA",
                        )
                    )
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, "IAM-008", "Usuários IAM não listados", {"error": str(err)})]
        raise
    return findings


def check_access_keys_age(account_id: str, iam_client) -> List[Finding]:
    findings: List[Finding] = []
    now = utc_now()
    paginator = iam_client.get_paginator("list_users")
    try:
        for page in paginator.paginate():
            for user in page.get("Users", []):
                user_name = user["UserName"]
                keys_page, err = safe_call(iam_client.list_access_keys, UserName=user_name)
                if err:
                    if is_access_denied(err):
                        findings.append(
                            _access_denied_finding(
                                account_id,
                                "IAM-003",
                                f"Chaves de acesso não listadas para o usuário {user_name}",
                                {"error": str(err), "user": user_name},
                            )
                        )
                        continue
                    raise err
                for key in keys_page.get("AccessKeyMetadata", []):
                    key_id = key["AccessKeyId"]
                    created = ensure_tz(key["CreateDate"])
                    age_days = (now - created).days
                    last_used_resp, err = safe_call(iam_client.get_access_key_last_used, AccessKeyId=key_id)
                    if err:
                        if is_access_denied(err):
                            findings.append(
                                _access_denied_finding(
                                    account_id,
                                    "IAM-003",
                                    f"Último uso da chave de acesso não verificado para {key_id}",
                                    {"error": str(err), "user": user_name, "access_key_id": key_id},
                                )
                            )
                            continue
                        raise err
                    last_used = last_used_resp.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                    last_used_days = None
                    if last_used:
                        last_used_days = (now - ensure_tz(last_used)).days
                    if age_days > 90 or (last_used_days is not None and last_used_days > 45) or last_used is None:
                        findings.append(
                            Finding(
                                account_id=account_id,
                                region=None,
                                domain="iam",
                                control_id="IAM-003",
                                severity="HIGH",
                                resource=key_id,
                                title="Chave de acesso antiga ou sem uso",
                                finding=(
                                    "Chave de acesso excede os limites de idade/uso (idade > 90 dias, último uso > 45 dias ou nunca usada)."
                                ),
                                remediation="Faça rotação ou exclua chaves de acesso antigas/não usadas.",
                                evidence={
                                    "user": user_name,
                                    "access_key_id": key_id,
                                    "age_days": age_days,
                                    "last_used_days": last_used_days,
                                },
                            )
                        )
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, "IAM-003", "Chaves de acesso não listadas", {"error": str(err)})]
        raise
    return findings


RISKY_ACTIONS = {"*", "iam:*"}


def _policy_is_risky(policy_doc: Dict[str, Any]) -> bool:
    statements = policy_doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        action = stmt.get("Action", [])
        resource = stmt.get("Resource", [])
        if isinstance(action, str):
            action = [action]
        if isinstance(resource, str):
            resource = [resource]
        if any(a in RISKY_ACTIONS or a.endswith(":*") for a in action):
            return True
        if any(r == "*" for r in resource):
            return True
    return False


def check_risky_customer_policies(account_id: str, iam_client) -> List[Finding]:
    findings: List[Finding] = []
    paginator = iam_client.get_paginator("list_policies")
    try:
        for page in paginator.paginate(Scope="Local"):
            for policy in page.get("Policies", []):
                policy_arn = policy["Arn"]
                policy_meta, err = safe_call(iam_client.get_policy, PolicyArn=policy_arn)
                if err:
                    if is_access_denied(err):
                        findings.append(
                            _access_denied_finding(
                                account_id,
                                "IAM-004",
                                f"Política não lida {policy_arn}",
                                {"error": str(err), "policy_arn": policy_arn},
                            )
                        )
                        continue
                    raise err
                version_id = policy_meta["Policy"]["DefaultVersionId"]
                version, err = safe_call(iam_client.get_policy_version, PolicyArn=policy_arn, VersionId=version_id)
                if err:
                    if is_access_denied(err):
                        findings.append(
                            _access_denied_finding(
                                account_id,
                                "IAM-004",
                                f"Versão da política não lida {policy_arn}",
                                {"error": str(err), "policy_arn": policy_arn},
                            )
                        )
                        continue
                    raise err
                doc = version["PolicyVersion"]["Document"]
                if _policy_is_risky(doc):
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=None,
                            domain="iam",
                            control_id="IAM-004",
                            severity="HIGH",
                            resource=policy_arn,
                            title="Política gerenciada pelo cliente é permissiva demais",
                            finding="A política contém ações ou recursos com curingas.",
                            remediation="Restrinja ações e recursos ao mínimo necessário.",
                            evidence={"policy_arn": policy_arn},
                        )
                    )
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, "IAM-004", "Políticas não listadas", {"error": str(err)})]
        raise
    return findings


def _trust_policy_risky(doc: Dict[str, Any]) -> bool:
    statements = doc.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    for stmt in statements:
        if stmt.get("Effect") != "Allow":
            continue
        principal = stmt.get("Principal", {})
        if principal == "*" or principal == {"AWS": "*"}:
            return True
        if isinstance(principal, dict):
            aws_principal = principal.get("AWS")
            if aws_principal == "*":
                return True
        condition = stmt.get("Condition")
        if principal and condition is None:
            return True
    return False


def check_risky_trust_policies(account_id: str, iam_client) -> List[Finding]:
    findings: List[Finding] = []
    paginator = iam_client.get_paginator("list_roles")
    try:
        for page in paginator.paginate():
            for role in page.get("Roles", []):
                role_name = role["RoleName"]
                policy_doc = role.get("AssumeRolePolicyDocument")
                if policy_doc and _trust_policy_risky(policy_doc):
                    findings.append(
                        Finding(
                            account_id=account_id,
                            region=None,
                            domain="iam",
                            control_id="IAM-005",
                            severity="HIGH",
                            resource=role.get("Arn", role_name),
                            title="Política de confiança da role IAM é permissiva demais",
                            finding="A política de confiança permite principais amplos sem condições.",
                            remediation="Restrinja os principais da política de confiança e adicione condições quando possível.",
                            evidence={"role": role_name, "assume_role_policy": policy_doc},
                        )
                    )
    except botocore.exceptions.ClientError as err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, "IAM-005", "Roles não listadas", {"error": str(err)})]
        raise
    return findings


def check_password_policy(account_id: str, iam_client) -> List[Finding]:
    findings: List[Finding] = []
    resp, err = safe_call(iam_client.get_account_password_policy)
    if err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, "IAM-006", "Política de senha não verificada", {"error": str(err)})]
        if isinstance(err, botocore.exceptions.ClientError):
            code = err.response.get("Error", {}).get("Code", "")
            if code == "NoSuchEntity":
                findings.append(
                    Finding(
                        account_id=account_id,
                        region=None,
                        domain="iam",
                        control_id="IAM-006",
                        severity="MEDIUM",
                        resource="password-policy",
                        title="Política de senha ausente",
                        finding="Não existe política de senha configurada na conta.",
                        remediation="Defina uma política de senha forte para usuários IAM locais.",
                        evidence={"policy_exists": False},
                        resource_type="iam-account",
                        risk_category="identity",
                        confidence="ALTA",
                    )
                )
                return findings
        raise err

    policy = resp.get("PasswordPolicy", {})
    min_length = policy.get("MinimumPasswordLength", 0)
    require_symbols = policy.get("RequireSymbols", False)
    require_numbers = policy.get("RequireNumbers", False)
    if min_length < 12 or not require_symbols or not require_numbers:
        findings.append(
            Finding(
                account_id=account_id,
                region=None,
                domain="iam",
                control_id="IAM-006",
                severity="MEDIUM",
                resource="password-policy",
                title="Política de senha fraca",
                finding="A política de senha não atende requisitos mínimos de complexidade.",
                remediation="Aumente o tamanho mínimo e exija números e símbolos.",
                evidence={
                    "minimum_length": min_length,
                    "require_symbols": require_symbols,
                    "require_numbers": require_numbers,
                },
                resource_type="iam-account",
                risk_category="identity",
                confidence="MEDIA",
            )
        )
    return findings


def check_root_access_keys(account_id: str, iam_client) -> List[Finding]:
    findings: List[Finding] = []
    resp, err = safe_call(iam_client.get_account_summary)
    if err:
        if is_access_denied(err):
            return [_access_denied_finding(account_id, "IAM-007", "Chaves da conta root não verificadas", {"error": str(err)})]
        raise err
    keys_present = resp.get("SummaryMap", {}).get("AccountAccessKeysPresent", 0)
    if int(keys_present) > 0:
        findings.append(
            Finding(
                account_id=account_id,
                region=None,
                domain="iam",
                control_id="IAM-007",
                severity="HIGH",
                resource="root-access-keys",
                title="Chaves de acesso ativas na conta root",
                finding="A conta root possui chaves de acesso ativas.",
                remediation="Remova chaves de acesso da conta root e use acesso federado com MFA.",
                evidence={"AccountAccessKeysPresent": keys_present},
                resource_type="root-account",
                risk_category="identity",
                confidence="ALTA",
            )
        )
    return findings


def run_iam_checks(account_id: str, session) -> List[Finding]:
    iam = get_client(session, "iam")
    findings: List[Finding] = []
    findings.extend(check_root_mfa(account_id, iam))
    findings.extend(check_users_exist(account_id, iam))
    findings.extend(check_users_without_mfa(account_id, iam))
    findings.extend(check_access_keys_age(account_id, iam))
    findings.extend(check_risky_customer_policies(account_id, iam))
    findings.extend(check_risky_trust_policies(account_id, iam))
    findings.extend(check_password_policy(account_id, iam))
    findings.extend(check_root_access_keys(account_id, iam))
    return findings
