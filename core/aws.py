from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

import boto3
import botocore
from botocore.config import Config

from core.logger import setup_logger


@dataclass
class AwsConfig:
    mode: str
    profile: Optional[str]
    role_arns: List[str]
    external_id: Optional[str]
    regions: List[str]


def base_session(profile: Optional[str] = None) -> boto3.Session:
    if profile:
        return boto3.Session(profile_name=profile)
    return boto3.Session()


def assume_role_session(base: boto3.Session, role_arn: str, external_id: Optional[str]) -> boto3.Session:
    sts = get_client(base, "sts")
    params = {
        "RoleArn": role_arn,
        "RoleSessionName": "aws-audit-mvp",
    }
    if external_id:
        params["ExternalId"] = external_id
    resp = sts.assume_role(**params)
    creds = resp["Credentials"]
    return boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )


def get_account_id(session: boto3.Session) -> str:
    sts = get_client(session, "sts")
    return sts.get_caller_identity()["Account"]


def get_client(session: boto3.Session, service: str, region: Optional[str] = None):
    config = Config(
        retries={"mode": "standard", "max_attempts": 10},
        connect_timeout=5,
        read_timeout=30,
        user_agent_extra="aws-audit-mvp",
    )
    return session.client(service, region_name=region, config=config)


def role_arn_to_account_id(role_arn: str) -> Optional[str]:
    parts = role_arn.split(":")
    if len(parts) > 4:
        return parts[4]
    return None


def session_for_target(config: AwsConfig) -> List[tuple[str, boto3.Session]]:
    logger = setup_logger()
    sessions: List[tuple[str, boto3.Session]] = []
    base = base_session(config.profile)
    if config.mode == "profile":
        account_id = get_account_id(base)
        sessions.append((account_id, base))
        return sessions

    if config.mode == "assume_role":
        for role_arn in config.role_arns:
            try:
                role_session = assume_role_session(base, role_arn, config.external_id)
                account_id = get_account_id(role_session)
                sessions.append((account_id, role_session))
            except botocore.exceptions.ClientError as exc:
                logger.error("Falha ao assumir a role %s: %s", role_arn, exc)
        return sessions

    raise ValueError("Modo não suportado; use 'profile' ou 'assume_role'")
