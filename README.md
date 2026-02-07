# AWS Audit MVP

Auditoria básica de AWS para IAM, Segurança e FinOps. Roda localmente com boto3 e gera achados em JSON (e CSV).

## Pré-requisitos
- Python 3.11+
- AWS CLI configurado (`aws configure`) e/ou acesso a roles cross-account
- Permissões para ler metadados de IAM, EC2, RDS, S3 e CloudTrail

## Instalação
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Configuração
Copie o exemplo:
```bash
cp config.example.yaml config.yaml
```

### Modo profile
```yaml
mode: profile
profile: default
regions:
  - us-east-1
```

### Modo assume_role
```yaml
mode: assume_role
profile: default
regions:
  - us-east-1
  - us-west-2
assume_role:
  role_arns:
    - arn:aws:iam::123456789012:role/AuditReadOnlyRole
    - arn:aws:iam::210987654321:role/AuditReadOnlyRole
  external_id: "optional-external-id"
```

### Política de tags
```yaml
tag_policy:
  required_tags:
    - Owner
    - Environment
  stopped_instance_days: 7
```

## Execução
```bash
python runner.py
```

Saídas:
- `outputs/findings-YYYYMMDD-HHMMSS.json`
- `outputs/findings-YYYYMMDD-HHMMSS.csv`

## Exemplo de saída
```
2026-01-29T12:34:56Z INFO aws-audit - Total de achados: 12
2026-01-29T12:34:56Z INFO aws-audit - Por severidade: {'HIGH': 4, 'MEDIUM': 6, 'LOW': 2}
2026-01-29T12:34:56Z INFO aws-audit - Por domínio: {'iam': 3, 'security': 5, 'finops': 4}
```

## Permissões necessárias (recomendado)
Use políticas gerenciadas da AWS quando possível e depois reduza para mínimo privilégio:
- `SecurityAudit` (gerenciada pela AWS)
- `ReadOnlyAccess` (gerenciada pela AWS)

Para cross-account, crie uma `AuditReadOnlyRole` que confia na conta auditora e anexe as políticas acima. Depois reduza para mínimo privilégio em produção.

## Controles incluídos
- IAM: MFA da root, usuários IAM, idade/uso de chaves, políticas arriscadas, políticas de confiança permissivas
- Segurança: S3 público, security groups, CloudTrail, criptografia padrão de EBS, criptografia de RDS
- FinOps: tags obrigatórias, instâncias paradas, volumes não anexados, EIPs não associados, ciclo de vida de S3

## Observações
- AccessDenied é reportado como achado INFO por controle e a auditoria continua.
- Suporte multi-região é configurado em `regions`.

## 🔐 Segurança e Qualidade de Código
Este projeto nasce com práticas DevSecOps desde o primeiro commit.

- **Bandit (SAST):** analisa o código Python em busca de padrões inseguros.
- **pip-audit (SCA):** verifica dependências com vulnerabilidades conhecidas (CVEs).
- **TruffleHog (segredos):** identifica possíveis segredos vazados no repositório.

### Como executar localmente
```bash
pip install -r requirements-dev.txt
bash scripts/security.sh
```

### Nota sobre DAST
DAST será adicionado somente quando existir uma API (por exemplo, com FastAPI).

### Recomendação para VS Code
```json
"python.analysis.typeCheckingMode": "basic"
```
