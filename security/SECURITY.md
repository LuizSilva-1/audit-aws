# Segurança do Projeto

## Princípios de segurança
- Segurança por padrão desde o primeiro commit (Secure-by-Design).
- Menor privilégio e segregação de funções.
- Falhas de permissão não interrompem a auditoria.
- Logs sem dados sensíveis e com redação básica.

## Política de credenciais
- NUNCA armazenar Access Keys no repositório.
- `config.yaml` é local e está no `.gitignore`.
- Preferência por autenticação via perfis do AWS CLI ou AssumeRole.

## Uso de AssumeRole
- Recomendado para auditoria cross-account.
- Permite escopo mínimo de permissões e isolamento por conta.

## Princípio do menor privilégio
- Use políticas gerenciadas como ponto de partida e refine para mínimo necessário.
- Evite permissões de escrita; o MVP é somente leitura.

## Coleta e armazenamento
- Coletamos apenas metadados necessários para achados de segurança e custo.
- Armazenamos achados e evidências técnicas em `outputs/`.

## O que NÃO coletamos
- Dados sensíveis do cliente (PII, conteúdo de buckets, dados de aplicações).
- Credenciais, chaves privadas ou tokens.
