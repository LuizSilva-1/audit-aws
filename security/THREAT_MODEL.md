# Modelo de Ameaças (MVP)

## Ativos protegidos
- Credenciais e sessões AWS usadas pela auditoria.
- Achados e evidências técnicas geradas localmente.

## Limites de confiança
- Ambiente local do auditor (máquina do desenvolvedor).
- AWS APIs (serviços chamados via boto3).
- Repositório Git e pipeline CI.

## Principais ameaças
- Exposição de segredos no repositório.
- Escopo excessivo de permissões IAM.
- Vazamento de dados sensíveis nos logs.
- Dependências com vulnerabilidades conhecidas.

## Mitigações aplicadas
- `.gitignore` forte e TruffleHog para varredura de segredos.
- Bandit para SAST e pip-audit para SCA.
- Configuração de cliente boto3 com timeouts e retries.
- Redação básica de logs e ausência de dumps de respostas.

## Premissas de segurança do MVP
- Execução local e controlada pelo fundador.
- Sem coleta de dados sensíveis do cliente.
- Sem interface web ou API pública.

## Limitações conhecidas
- Não há DAST enquanto não existir API.
- Auditoria depende de permissões corretas em cada conta.
- Cobertura de controles é propositalmente mínima para o MVP.
