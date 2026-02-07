from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Tuple

from core.models import Finding


SEVERITY_ORDER = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
RISK_WEIGHT = {
    "exposure": 5,
    "identity": 4,
    "encryption": 4,
    "logging": 3,
    "cost": 2,
    "governance": 1,
}


def enrich_findings(findings: List[Finding]) -> List[Finding]:
    for f in findings:
        if f.resource_type is None:
            f.resource_type = _resource_type_for_control(f.control_id)
        if f.risk_category is None:
            f.risk_category = _risk_category_for_control(f.control_id)
        if f.confidence is None:
            f.confidence = _confidence_for_control(f.control_id)
        if f.references is None:
            f.references = _references_for_control(f.control_id)
        if f.display_name is None:
            f.display_name = _display_name_from_evidence(f)
    return findings


def _resource_type_for_control(control_id: str) -> str | None:
    mapping = {
        "IAM-001": "root-account",
        "IAM-002": "iam-user",
        "IAM-003": "access-key",
        "IAM-004": "iam-policy",
        "IAM-005": "iam-role",
        "IAM-006": "iam-account",
        "IAM-007": "root-account",
        "IAM-008": "iam-user",
        "S3-001": "s3-bucket",
        "S3-002": "s3-bucket",
        "S3-003": "s3-bucket",
        "S3-004": "s3-bucket",
        "EC2-001": "security-group",
        "LOG-001": "cloudtrail",
        "ENC-001": "ebs",
        "RDS-001": "rds-instance",
        "GOV-002": "cloudtrail",
        "FIN-001": "ec2-instance",
        "FIN-002": "ec2-instance",
        "FIN-003": "ebs-volume",
        "FIN-004": "elastic-ip",
        "FIN-005": "s3-bucket",
        "FIN-006": "ebs-snapshot",
        "FIN-007": "load-balancer",
        "FIN-008": "rds-instance",
        "FIN-009": "ebs-volume",
        "FIN-010": "ebs-snapshot",
        "FIN-011": "ebs-volume",
        "GOV-001": "rds-instance",
        "GOV-003": "aws-config",
        "GOV-004": "aws-region",
    }
    return mapping.get(control_id)


def _risk_category_for_control(control_id: str) -> str | None:
    mapping = {
        "IAM-001": "identity",
        "IAM-002": "identity",
        "IAM-003": "identity",
        "IAM-004": "identity",
        "IAM-005": "identity",
        "IAM-006": "identity",
        "IAM-007": "identity",
        "IAM-008": "identity",
        "S3-001": "exposure",
        "S3-002": "cost",
        "S3-003": "governance",
        "S3-004": "encryption",
        "EC2-001": "exposure",
        "LOG-001": "logging",
        "ENC-001": "encryption",
        "RDS-001": "encryption",
        "GOV-002": "governance",
        "FIN-001": "cost",
        "FIN-002": "cost",
        "FIN-003": "cost",
        "FIN-004": "cost",
        "FIN-005": "cost",
        "FIN-006": "cost",
        "FIN-007": "cost",
        "FIN-008": "cost",
        "FIN-009": "cost",
        "FIN-010": "cost",
        "FIN-011": "cost",
        "GOV-001": "governance",
        "GOV-003": "governance",
        "GOV-004": "governance",
    }
    return mapping.get(control_id)


def _confidence_for_control(control_id: str) -> str:
    if control_id in {"IAM-001", "IAM-007", "S3-001", "S3-004", "EC2-001", "LOG-001", "ENC-001", "RDS-001"}:
        return "ALTA"
    if control_id in {"FIN-001", "FIN-002", "FIN-003", "FIN-004", "FIN-005", "FIN-006", "FIN-007", "FIN-008", "FIN-009", "FIN-010", "FIN-011", "S3-002", "S3-003", "IAM-003", "IAM-006", "IAM-008", "GOV-001", "GOV-002", "GOV-003", "GOV-004"}:
        return "MEDIA"
    return "BAIXA"


def _references_for_control(control_id: str) -> List[str]:
    mapping = {
        "IAM-001": ["AWS Well-Architected - Segurança"],
        "IAM-006": ["AWS Well-Architected - Segurança"],
        "IAM-007": ["AWS Well-Architected - Segurança"],
        "IAM-008": ["AWS Well-Architected - Segurança"],
        "S3-001": ["AWS Well-Architected - Segurança"],
        "S3-003": ["AWS Well-Architected - Segurança"],
        "S3-004": ["AWS Well-Architected - Segurança"],
        "EC2-001": ["AWS Well-Architected - Segurança"],
        "LOG-001": ["AWS Well-Architected - Segurança"],
        "ENC-001": ["AWS Well-Architected - Segurança"],
        "RDS-001": ["AWS Well-Architected - Segurança"],
        "GOV-002": ["AWS Well-Architected - Excelência Operacional"],
        "FIN-001": ["AWS Well-Architected - Otimização de Custos"],
        "FIN-002": ["AWS Well-Architected - Otimização de Custos"],
        "FIN-003": ["AWS Well-Architected - Otimização de Custos"],
        "FIN-004": ["AWS Well-Architected - Otimização de Custos"],
        "FIN-005": ["AWS Well-Architected - Otimização de Custos"],
        "FIN-006": ["AWS Well-Architected - Otimização de Custos"],
        "FIN-007": ["AWS Well-Architected - Otimização de Custos"],
        "FIN-008": ["AWS Well-Architected - Otimização de Custos"],
        "FIN-009": ["AWS Well-Architected - Otimização de Custos"],
        "FIN-010": ["AWS Well-Architected - Otimização de Custos"],
        "FIN-011": ["AWS Well-Architected - Otimização de Custos"],
        "GOV-001": ["AWS Well-Architected - Excelência Operacional"],
        "GOV-003": ["AWS Well-Architected - Excelência Operacional"],
        "GOV-004": ["AWS Well-Architected - Excelência Operacional"],
        "S3-002": ["AWS Well-Architected - Otimização de Custos"],
    }
    return mapping.get(control_id, [])


def _display_name_from_evidence(finding: Finding) -> str | None:
    evidence = finding.evidence or {}
    if finding.control_id == "IAM-003":
        return evidence.get("user")
    if finding.control_id == "FIN-001":
        return evidence.get("name_tag")
    if finding.control_id == "EC2-001":
        return evidence.get("security_group_name")
    if finding.control_id == "RDS-001":
        return evidence.get("db_instance")
    return None


def summary_counters(findings: Iterable[Finding]) -> Tuple[Counter, Counter]:
    severity = Counter()
    domain = Counter()
    for f in findings:
        severity[f.severity] += 1
        domain[f.domain] += 1
    return severity, domain


def group_by_resource(findings: Iterable[Finding]) -> Dict[str, List[Finding]]:
    grouped: Dict[str, List[Finding]] = defaultdict(list)
    for f in findings:
        key = f.resource
        if f.display_name:
            key = f"{f.resource} (Name={f.display_name})"
        grouped[key].append(f)
    return grouped


def top_actions(findings: List[Finding], limit: int = 5) -> List[Finding]:
    def score(f: Finding) -> int:
        return SEVERITY_ORDER.get(f.severity, 1) * 10 + RISK_WEIGHT.get(f.risk_category or "governance", 1)

    ordered = sorted(findings, key=score, reverse=True)
    seen = set()
    result: List[Finding] = []
    for f in ordered:
        key = (f.control_id, f.resource, f.region)
        if key in seen:
            continue
        seen.add(key)
        result.append(f)
        if len(result) >= limit:
            break
    return result


def _gerar_top_recursos_vulneraveis(findings: List[Finding]) -> str:
    """Gera HTML para os top recursos mais vulneráveis em formato compacto"""
    agrupado = group_by_resource(findings)
    ordenado = ordenar_por_importancia(agrupado)
    
    linhas = ["<div style=\"display:grid;grid-template-columns:repeat(2,1fr);gap:16px\">"]
    for recurso, itens in list(ordenado.items())[:4]:
        controles = sorted({i.control_id for i in itens})
        display_name = itens[0].display_name if itens[0].display_name else recurso
        
        linhas.append(f"<div class=\"vuln-resource-compact\">")
        linhas.append(f"<div style=\"display:flex;align-items:center;justify-content:space-between;margin-bottom:8px\">")
        linhas.append(f"<span style=\"font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:800;color:#dc2626\">{display_name}</span>")
        linhas.append(f"<span style=\"font-size:11px;font-weight:900;color:#94a3b8\">{len(controles)} issue{'s' if len(controles)>1 else ''}</span>")
        linhas.append(f"</div>")
        linhas.append(f"<div style=\"display:flex;flex-wrap:wrap;gap:6px\">")
        for ctrl in controles[:5]:
            finding = next(f for f in itens if f.control_id == ctrl)
            sev_color = {"CRITICAL": "#dc2626", "HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#10b981", "INFO": "#64748b"}.get(finding.severity, "#64748b")
            linhas.append(f"<span style=\"display:inline-flex;padding:4px 8px;background:rgba(239,68,68,.08);border-radius:12px;font-size:10px;font-weight:800;color:{sev_color};border:1px solid rgba(239,68,68,.2)\">{ctrl}</span>")
        if len(controles) > 5:
            linhas.append(f"<span style=\"font-size:10px;color:#94a3b8;padding:4px 8px\">+{len(controles)-5} mais</span>")
        linhas.append(f"</div>")
        linhas.append(f"</div>")
    linhas.append("</div>")
    
    return "\n".join(linhas)


def console_summary(findings: List[Finding]) -> str:
    severity, domain = summary_counters(findings)
    linhas = [
        f"Total de achados: {len(findings)}",
        f"Por severidade: {dict(severity)}",
        f"Por domínio: {dict(domain)}",
    ]
    top = top_actions(findings)
    linhas.append("Top 5 ações recomendadas:")
    for f in top:
        linhas.append(f"- {f.severity} {f.control_id}: {f.title} -> {f.resource}")
    agrupado = group_by_resource(findings)
    linhas.append("Achados por recurso:")
    for recurso, itens in list(ordenar_por_importancia(agrupado).items())[:5]:
        controles = ", ".join(sorted({i.control_id for i in itens}))
        linhas.append(f"- {recurso} -> {controles}")
    return "\n".join(linhas)


def ordenar_por_importancia(agrupado: Dict[str, List[Finding]]) -> Dict[str, List[Finding]]:
    def score(itens: List[Finding]) -> int:
        return max(SEVERITY_ORDER.get(i.severity, 1) for i in itens) * 100 + len(itens)

    return dict(sorted(agrupado.items(), key=lambda kv: score(kv[1]), reverse=True))


def gerar_relatorio_markdown(findings: List[Finding], ts: str, tag_recomendadas: List[str], score_obj: Dict[str, Any]) -> str:
    top = top_actions(findings)
    total = len(findings)
    severidade, dominio = summary_counters(findings)
    excecoes = [f for f in findings if f.is_exception]

    tem_fin_008 = any(f.control_id == "FIN-008" for f in findings)
    resumo = (
        f"Nesta execução foram identificados {total} achados. "
        f"As severidades mais relevantes são: {_formatar_contagens(severidade)}. "
        f"Domínios afetados: {_formatar_contagens(dominio)}."
    )
    if tem_fin_008:
        resumo += " Observação FinOps: retenções de backup do RDS acima de 7 dias são tratadas como oportunidade de otimização de custos."

    linhas = [
        f"# Relatório Executivo - {ts}",
        "",
        "## Resumo executivo",
        resumo,
        "",
        "## Top ações",
        "| Severidade | Ação | Recurso | Como corrigir |",
        "|---|---|---|---|",
    ]
    for f in top:
        recurso = f.resource
        if f.display_name:
            recurso = f"{recurso} (Name={f.display_name})"
        linhas.append(f"| {f.severity} | {f.title} | {recurso} | {f.remediation} |")

    linhas.append("")
    linhas.append("## Seção por domínio")
    for dominio_nome in ["iam", "security", "finops", "governance"]:
        itens = [f for f in findings if f.domain == dominio_nome]
        if not itens:
            continue
        linhas.append(f"### {dominio_nome.upper()}")
        for f in itens:
            linhas.append(f"- {f.severity} {f.control_id}: {f.title} ({f.resource})")
        linhas.append("")

    linhas.append("## Exceções aplicadas")
    if excecoes:
        for f in excecoes:
            linhas.append(f"- {f.control_id} em {f.resource}: {f.title}")
    else:
        linhas.append("- Nenhuma exceção aplicada")

    linhas.append("")
    linhas.append("## 📊 Score de Maturidade AWS")
    linhas.append("| Domínio | Score |")
    linhas.append("|---|---|")
    for dom in ["security", "iam", "finops"]:
        linhas.append(f"| {dom} | {score_obj['domains'].get(dom, 100)} |")
    linhas.append(f"| Geral | {score_obj['overall']} |")
    linhas.append("Interpretação: quanto maior o score, melhor a maturidade de segurança e custo para este domínio.")

    linhas.append("")
    if tem_fin_008:
        linhas.append("## Observações FinOps")
        linhas.append("Retenções de backup do RDS acima de 7 dias são tratadas como oportunidade de otimização de custos.")
        linhas.append("")
    linhas.append("## Detalhes técnicos")
    for f in findings:
        reg = f.region or "global"
        dn = f" (Name={f.display_name})" if f.display_name else ""
        linhas.append(f"- [{f.severity}] {f.control_id} {f.resource}{dn} ({reg}) - {f.finding}")

    tem_fin_001 = any(f.control_id == "FIN-001" for f in findings)
    if tag_recomendadas and tem_fin_001:
        linhas.append("")
        linhas.append("## Tags recomendadas")
        linhas.append(f"Tags obrigatórias configuradas: {', '.join(tag_recomendadas)}")
        linhas.append("Exemplo de valores: Owner=EquipeX, Environment=prod")

    return "\n".join(linhas)


def gerar_relatorio_html(findings: List[Finding], ts: str, tag_recomendadas: List[str], score_obj: Dict[str, Any]) -> str:
    top = top_actions(findings)
    total = len(findings)
    severidade, dominio = summary_counters(findings)
    excecoes = [f for f in findings if f.is_exception]
    tem_fin_008 = any(f.control_id == "FIN-008" for f in findings)
    tem_fin_001 = any(f.control_id == "FIN-001" for f in findings)
    dominio_controles: Dict[str, Dict[str, int]] = {}
    for d in ["iam", "security", "finops"]:
        controles = {}
        for f in findings:
            if f.domain != d:
                continue
            controles[f.control_id] = controles.get(f.control_id, 0) + 1
        dominio_controles[d] = controles

    resumo = (
        f"Nesta execução foram identificados {total} achados. "
        f"As severidades mais relevantes são: {_formatar_contagens(severidade)}. "
        f"Domínios afetados: {_formatar_contagens(dominio)}."
    )
    if tem_fin_008:
        resumo += " Observação FinOps: retenções de backup do RDS acima de 7 dias são tratadas como oportunidade de otimização de custos."

    def esc(text: Any) -> str:
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    sev_class = {
        "CRITICAL": "sev-critical",
        "HIGH": "sev-high",
        "MEDIUM": "sev-medium",
        "LOW": "sev-low",
        "INFO": "sev-info",
    }

    linhas = [
        "<!doctype html>",
        "<html lang=\"pt-BR\">",
        "<head>",
        "<meta charset=\"utf-8\"/>",
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"/>",
        f"<title>Relatório AWS Audit MVP - {esc(ts)}</title>",
        "<style>",
        "*{box-sizing:border-box;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale}:root{--ink:#0a0f1e;--muted:#64748b;--bg:#f8fafc;--card:#ffffff;--brand:#06b6d4;--brand2:#0284c7;--accent:#0f172a;--success:#10b981;--warning:#f59e0b;--error:#ef4444;--critical:#dc2626;--shadow-sm:0 1px 3px rgba(0,0,0,.05),0 1px 2px rgba(0,0,0,.03);--shadow-md:0 4px 12px rgba(0,0,0,.08),0 2px 4px rgba(0,0,0,.04);--shadow-lg:0 20px 40px rgba(0,0,0,.12),0 8px 16px rgba(0,0,0,.08);--shadow-xl:0 24px 48px rgba(0,0,0,.15),0 12px 24px rgba(0,0,0,.1);--radius:18px;--transition:all .35s cubic-bezier(.4,0,.2,1);--glow:0 0 20px rgba(6,182,212,.3)}body.dark{--ink:#f8fafc;--muted:#94a3b8;--bg:#0a0f1e;--card:#1e293b;--accent:#f8fafc;background:#0a0f1e}body.dark .hero{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border-color:rgba(255,255,255,.05)}body.dark .card,body.dark table,body.dark .list,body.dark .summary-box,body.dark .details{background:linear-gradient(135deg,#1e293b 0%,#1a2332 100%);color:var(--ink);border-color:rgba(148,163,184,.2)}body.dark th{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%)}body.dark tbody tr:hover{background:linear-gradient(90deg,rgba(6,182,212,.1) 0%,transparent 100%)}body.dark .score-display{background:linear-gradient(135deg,#1e293b,#1a2332);border-left-color:var(--brand)}body.dark h2{color:var(--ink)}",
        "html{scroll-behavior:smooth}body{font-family:-apple-system,BlinkMacSystemFont,'Inter','Segoe UI','Helvetica Neue',sans-serif;color:var(--ink);margin:0;background:radial-gradient(circle at 10% 20%,#f0f9ff 0%,#f8fafc 40%,#fff 100%);line-height:1.7;letter-spacing:-.015em;min-height:100vh}",
        ".wrap{max-width:1280px;margin:0 auto;padding:48px 32px}",
        ".hero{background:linear-gradient(135deg,#0c4a6e 0%,#0a0f1e 100%);color:#fff;padding:64px 48px;border-radius:28px;box-shadow:var(--shadow-xl),0 0 60px rgba(6,182,212,.15);position:relative;overflow:hidden;border:1px solid rgba(255,255,255,.1)}",
        ".hero:before{content:'';position:absolute;top:-40%;right:-15%;width:700px;height:700px;background:radial-gradient(circle,rgba(6,182,212,.2) 0%,transparent 65%);border-radius:50%;filter:blur(60px);pointer-events:none;animation:float 8s ease-in-out infinite}",
        ".hero:after{content:'';position:absolute;left:-15%;bottom:-40%;width:600px;height:600px;background:radial-gradient(circle,rgba(99,102,241,.15) 0%,transparent 65%);border-radius:50%;filter:blur(60px);pointer-events:none;animation:float 10s ease-in-out infinite reverse}",
        "@keyframes float{0%,100%{transform:translate(0,0)}50%{transform:translate(30px,-30px)}}",
        ".hero-content{position:relative;z-index:1}",
        ".hero h1{margin:0 0 20px;font-size:48px;font-weight:900;letter-spacing:-1.5px;line-height:1.05;text-shadow:0 4px 24px rgba(0,0,0,.3);background:linear-gradient(135deg,#fff 0%,#cbd5e1 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}",
        ".hero p{margin:0;color:#e0e7ff;font-size:17px;line-height:1.7;max-width:650px;text-shadow:0 2px 8px rgba(0,0,0,.2)}",
        ".grid{display:grid;grid-template-columns:repeat(6,1fr);gap:20px;margin-top:36px}",
        ".card{background:linear-gradient(135deg,#ffffff 0%,#fafbfc 100%);border-radius:var(--radius);padding:28px;box-shadow:var(--shadow-sm);border:1px solid rgba(148,163,184,.12);color:var(--ink);transition:var(--transition);position:relative;overflow:hidden;backdrop-filter:blur(10px)}",
        ".card:hover{transform:translateY(-6px) scale(1.02);box-shadow:var(--shadow-md),var(--glow);border-color:rgba(6,182,212,.3)}",
        ".card:before{content:'';position:absolute;top:0;left:0;right:0;height:5px;background:linear-gradient(90deg,#06b6d4,#0284c7,#6366f1);opacity:.9}",
        ".card:after{content:'';position:absolute;inset:0;background:radial-gradient(circle at 50% 0%,rgba(6,182,212,.04),transparent);pointer-events:none}",
        ".card h3{margin:0 0 14px;font-size:11px;text-transform:uppercase;letter-spacing:1.5px;color:#64748b;font-weight:800;position:relative;z-index:1}",
        ".card .val{font-size:40px;font-weight:950;background:linear-gradient(135deg,#0284c7 0%,#6366f1 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;line-height:.95;letter-spacing:-2px;position:relative;z-index:1}",
        ".card .sub{font-size:13px;color:#94a3b8;margin-top:10px;font-weight:600;position:relative;z-index:1}",
        "h2{margin:56px 0 28px;font-size:32px;font-weight:900;color:var(--ink);padding-bottom:18px;border-bottom:4px solid transparent;background:linear-gradient(90deg,var(--brand) 0%,var(--brand) 60px,transparent 60px);background-position:bottom;background-size:100% 4px;background-repeat:no-repeat;display:inline-block;letter-spacing:-1px}",
        "h3{margin:24px 0 14px;font-size:18px;font-weight:800;color:var(--ink);letter-spacing:-.5px}",
        "p{color:#475569;line-height:1.8;font-size:15px}",
        "table{border-collapse:separate;border-spacing:0;width:100%;margin:28px 0 36px;background:linear-gradient(135deg,#fff 0%,#fafbfc 100%);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow-md);border:1px solid rgba(148,163,184,.12)}",
        "th{background:linear-gradient(135deg,#f8fafc 0%,#f1f5f9 100%);color:#1e293b;font-weight:900;padding:20px 16px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:.8px;border-bottom:3px solid #e2e8f0}",
        "td{border-bottom:1px solid #f1f5f9;padding:18px 16px;text-align:left;font-size:15px;color:#475569;transition:var(--transition)}",
        "tbody tr{transition:var(--transition);cursor:default}tbody tr:hover{background:linear-gradient(90deg,rgba(6,182,212,.04) 0%,transparent 100%);transform:scale(1.01)}",
        "tbody tr:hover td:first-child{border-left:4px solid var(--brand);padding-left:12px}",
        ".muted{color:#94a3b8;font-size:14px;font-weight:500}",
        ".badge{display:inline-flex;align-items:center;justify-content:center;padding:8px 14px;border-radius:28px;font-size:11px;font-weight:900;letter-spacing:.5px;text-transform:uppercase;box-shadow:var(--shadow-sm);transition:var(--transition);border:1px solid transparent}",
        ".badge:hover{transform:translateY(-2px) scale(1.05);box-shadow:var(--shadow-md)}",
        ".sev-critical{background:linear-gradient(135deg,#dc2626,#b91c1c);color:#fff;box-shadow:0 4px 16px rgba(220,38,38,.4);border-color:rgba(220,38,38,.3)}",
        ".sev-high{background:linear-gradient(135deg,#ef4444,#dc2626);color:#fff;box-shadow:0 4px 16px rgba(239,68,68,.4);border-color:rgba(239,68,68,.3)}",
        ".sev-medium{background:linear-gradient(135deg,#f59e0b,#d97706);color:#fff;box-shadow:0 4px 16px rgba(245,158,11,.4);border-color:rgba(245,158,11,.3)}",
        ".sev-low{background:linear-gradient(135deg,#10b981,#059669);color:#fff;box-shadow:0 4px 16px rgba(16,185,129,.4);border-color:rgba(16,185,129,.3)}",
        ".sev-info{background:linear-gradient(135deg,#64748b,#475569);color:#fff;box-shadow:0 4px 16px rgba(100,116,139,.4);border-color:rgba(100,116,139,.3)}",
        ".section{margin-top:56px;padding-top:28px;animation:fadeSlideIn .6s ease-out}",
        "@keyframes fadeSlideIn{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}",
        ".section:first-child{margin-top:0}",
        ".domain-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:24px;margin-top:28px}",
        ".list{background:linear-gradient(135deg,#fff 0%,#fafbfc 100%);border-radius:var(--radius);padding:28px;box-shadow:var(--shadow-sm);border:1px solid rgba(148,163,184,.12);transition:var(--transition);position:relative;overflow:hidden}",
        ".list:hover{transform:translateY(-4px);box-shadow:var(--shadow-md),var(--glow);border-color:rgba(6,182,212,.25)}",
        ".list:before{content:'';position:absolute;top:0;left:0;width:5px;height:100%;background:linear-gradient(180deg,#06b6d4,#0284c7,#6366f1);border-radius:var(--radius) 0 0 var(--radius)}",
        ".list:after{content:'';position:absolute;inset:0;background:radial-gradient(circle at 0% 50%,rgba(6,182,212,.03),transparent 50%);pointer-events:none}",
        ".list h3{margin-top:0;padding-left:16px;position:relative;z-index:1}",
        ".list ul{margin:18px 0 0 32px;padding:0;list-style:none;position:relative;z-index:1}",
        ".list li{margin:12px 0;font-size:15px;color:#475569;transition:var(--transition);padding-left:16px;position:relative}",
        ".list li:before{content:'▸';position:absolute;left:0;color:var(--brand);font-weight:bold;transition:var(--transition)}",
        ".list li:hover{color:var(--brand);transform:translateX(6px)}",
        ".list li:hover:before{transform:translateX(4px)}",
        ".chip{display:inline-flex;align-items:center;gap:10px;padding:12px 18px;border-radius:28px;background:rgba(255,255,255,.25);color:#fff;border:1.5px solid rgba(255,255,255,.5);font-size:13px;font-weight:800;backdrop-filter:blur(20px);transition:var(--transition);box-shadow:0 4px 12px rgba(0,0,0,.1)}",
        ".chip:hover{background:rgba(255,255,255,.35);border-color:rgba(255,255,255,.7);transform:translateY(-3px);box-shadow:0 8px 20px rgba(0,0,0,.15)}",
        ".toolbar{display:flex;gap:14px;flex-wrap:wrap;margin-top:24px;align-items:center}",
        ".details{background:linear-gradient(135deg,#fff 0%,#fafbfc 100%);border-radius:var(--radius);padding:28px;box-shadow:var(--shadow-sm);border:1px solid rgba(148,163,184,.12)}",
        "details{cursor:pointer}details summary{font-weight:900;padding:16px;color:var(--brand);display:flex;align-items:center;gap:12px;user-select:none;transition:var(--transition);font-size:16px;border-radius:12px}",
        "details summary:hover{color:#0284c7;background:rgba(6,182,212,.05);transform:translateX(6px)}",
        "details[open] summary{color:var(--brand);font-weight:900;background:rgba(6,182,212,.08)}",
        ".summary{display:grid;grid-template-columns:1.2fr .8fr;gap:24px;margin-top:24px}",
        ".summary-box{background:linear-gradient(135deg,#fff 0%,#fafbfc 100%);border-radius:var(--radius);padding:28px;border:1px solid rgba(148,163,184,.12);box-shadow:var(--shadow-sm);transition:var(--transition);position:relative;overflow:hidden}",
        ".summary-box:hover{border-color:rgba(6,182,212,.25);box-shadow:var(--shadow-md)}",
        ".summary-box:before{content:'';position:absolute;top:0;right:0;width:120px;height:120px;background:radial-gradient(circle,rgba(6,182,212,.06),transparent);border-radius:50%;pointer-events:none}",
        ".severity-strip{display:flex;flex-wrap:wrap;gap:14px;margin-top:18px}",
        ".strip{display:inline-flex;align-items:center;gap:12px;padding:11px 16px;border-radius:28px;font-size:13px;font-weight:900;background:linear-gradient(135deg,#f1f5f9,#e2e8f0);color:#0f172a;border:1px solid #cbd5e1;box-shadow:var(--shadow-sm);transition:var(--transition)}",
        ".strip:hover{transform:translateY(-3px);box-shadow:var(--shadow-md);background:linear-gradient(135deg,#e2e8f0,#cbd5e1)}",
        ".strip .dot{width:14px;height:14px;border-radius:50%;box-shadow:0 0 12px currentColor,inset 0 0 4px rgba(0,0,0,.1);animation:pulse 2.5s ease-in-out infinite}",
        "@keyframes pulse{0%,100%{box-shadow:0 0 12px currentColor,inset 0 0 4px rgba(0,0,0,.1)}50%{box-shadow:0 0 20px currentColor,inset 0 0 6px rgba(0,0,0,.15)}}",
        ".pill{display:inline-flex;align-items:center;gap:7px;padding:8px 14px;border-radius:28px;background:linear-gradient(135deg,#e2e8f0,#f1f5f9);color:#1e293b;font-size:11px;font-weight:900;border:1px solid #cbd5e1;text-transform:uppercase;letter-spacing:.5px;box-shadow:var(--shadow-sm);transition:var(--transition)}",
        ".pill:hover{transform:scale(1.08) translateY(-2px);box-shadow:var(--shadow-md);background:linear-gradient(135deg,#cbd5e1,#e2e8f0)}",
        ".dot-high{background:#ef4444}",
        ".dot-medium{background:#f59e0b}",
        ".dot-low{background:#10b981}",
        ".dot-info{background:#64748b}",
        ".dot-critical{background:#dc2626}",
        ".score-note{font-size:14px;color:#64748b;margin-top:14px;font-style:italic;font-weight:600;position:relative;padding-left:20px}",
        ".score-note:before{content:'💡';position:absolute;left:0;font-size:16px}",
        ".progress-bar{width:100%;height:10px;background:#e2e8f0;border-radius:6px;overflow:hidden;margin:14px 0;box-shadow:inset 0 2px 6px rgba(0,0,0,.08);position:relative}",
        ".progress-bar:after{content:'';position:absolute;inset:0;background:linear-gradient(90deg,transparent,rgba(255,255,255,.3),transparent);animation:shimmer 2s infinite}",
        "@keyframes shimmer{0%{transform:translateX(-100%)}100%{transform:translateX(100%)}}",
        ".progress-fill{height:100%;background:linear-gradient(90deg,#06b6d4,#0284c7,#6366f1);border-radius:6px;transition:width .5s cubic-bezier(.4,0,.2,1);box-shadow:0 2px 12px rgba(6,182,212,.5),inset 0 1px 2px rgba(255,255,255,.3);position:relative}",
        ".score-display{display:flex;align-items:center;justify-content:space-between;gap:20px;padding:20px 24px;background:linear-gradient(135deg,#f8fafc,#f1f5f9);border-radius:14px;margin:16px 0;border-left:5px solid var(--brand);box-shadow:var(--shadow-sm);transition:var(--transition)}",
        ".score-display:hover{transform:translateX(6px);box-shadow:var(--shadow-md);border-left-width:6px}",
        ".score-label{font-size:13px;color:#64748b;text-transform:uppercase;font-weight:800;letter-spacing:.6px}",
        ".score-val{font-size:32px;font-weight:950;background:linear-gradient(135deg,#0284c7,#6366f1);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;letter-spacing:-1px}",
        "@media(max-width:1200px){.grid{grid-template-columns:repeat(3,1fr)}.domain-grid{grid-template-columns:1fr}}",
        "@media(max-width:768px){.grid{grid-template-columns:repeat(2,1fr)}.domain-grid{grid-template-columns:1fr}.summary{grid-template-columns:1fr}.hero{padding:40px 24px}.hero h1{font-size:32px}.hero p{font-size:14px}.wrap{padding:24px 16px}.card{padding:18px}}",
        "@media(max-width:480px){.grid{grid-template-columns:1fr}.toolbar{gap:8px;flex-direction:column;align-items:flex-start}.chip{padding:8px 12px;font-size:11px}.hero h1{font-size:26px}.wrap{padding:16px 12px}table{font-size:12px}th,td{padding:10px 8px}.dark-toggle{top:16px;right:16px;padding:12px;font-size:18px}}",
        ".search-box{position:relative;margin:28px 0}.search-box input{width:100%;padding:16px 50px 16px 20px;border-radius:16px;border:2px solid #e2e8f0;font-size:15px;background:linear-gradient(135deg,#fff,#f8fafc);transition:var(--transition);box-shadow:var(--shadow-sm);font-family:inherit}.search-box input:focus{outline:none;border-color:var(--brand);box-shadow:var(--shadow-md),0 0 0 4px rgba(6,182,212,.1)}.search-box:after{content:'🔍';position:absolute;right:18px;top:50%;transform:translateY(-50%);font-size:18px;pointer-events:none}.dark-toggle{position:fixed;top:24px;right:24px;background:linear-gradient(135deg,var(--brand),var(--brand2));color:#fff;border:none;padding:14px 16px;border-radius:50%;font-size:20px;cursor:pointer;box-shadow:var(--shadow-lg);transition:var(--transition);z-index:1000}.dark-toggle:hover{transform:scale(1.15) rotate(15deg);box-shadow:var(--shadow-xl)}",
        ".vuln-resource-compact{background:linear-gradient(135deg,rgba(239,68,68,.06),rgba(239,68,68,.02));border-left:3px solid #ef4444;border-radius:12px;padding:14px 16px;transition:var(--transition);box-shadow:0 1px 3px rgba(0,0,0,.05);border:1px solid rgba(239,68,68,.15)}.vuln-resource-compact:hover{transform:translateY(-2px);box-shadow:0 4px 12px rgba(239,68,68,.15);border-left-width:4px}",
        "</style>",
        "</head>",
        "<body>",
        "<button class=\"dark-toggle\" onclick=\"document.body.classList.toggle('dark');this.textContent=document.body.classList.contains('dark')?'☀️':'🌙'\" title=\"Alternar tema\">🌙</button>",
        "<div class=\"wrap\">",
        "<div class=\"hero\">",
        "<div class=\"hero-content\">",
        f"<h1>📊 Relatório Executivo AWS Audit</h1>",
        f"<p>Gerado em <strong>{esc(ts)}</strong> • Escopo: <strong>IAM, Segurança e FinOps</strong></p>",
        "<div class=\"toolbar\">",
        "<span class=\"chip\">🔐 SecurityAudit</span>",
        "<span class=\"chip\">📖 ReadOnlyAccess</span>",
        "<span class=\"chip\">✅ Zero modificações</span>",
        "</div>",
        "</div>",
        "<div class=\"grid\" style=\"grid-template-columns:repeat(2,1fr);gap:20px\">",
        "<div class=\"card\" style=\"grid-column:1/-1\"><h3>🎯 Visão Geral</h3><div style=\"display:grid;grid-template-columns:1fr 1fr;gap:20px\"><div><div class=\"val\">"+esc(total)+"</div><div class=\"sub\">Total de achados</div></div><div style=\"border-left:2px solid var(--brand);padding-left:20px\"><div class=\"val\">"+esc(score_obj['overall'])+"</div><div class=\"sub\">Score geral (ponderado)</div></div></div></div>",
        "<div class=\"card\" style=\"background:linear-gradient(135deg,rgba(20,184,166,.1),rgba(20,184,166,.05));border-left:4px solid #14b8a6\"><h3 style=\"color:#0d9488\">✅ SECURITY</h3><div class=\"val\" style=\"color:#0d9488\">"+esc(score_obj['domains'].get('security',0))+"</div><div class=\"sub\">Proteção de dados (peso: 50%)</div></div>",
        "<div class=\"card\" style=\"background:linear-gradient(135deg,rgba(59,130,246,.1),rgba(59,130,246,.05));border-left:4px solid #3b82f6\"><h3 style=\"color:#1e40af\">🔐 IAM</h3><div class=\"val\" style=\"color:#1e40af\">"+esc(score_obj['domains'].get('iam',0))+"</div><div class=\"sub\">Identidade (peso: 30%)</div></div>",
        "<div class=\"card\" style=\"background:linear-gradient(135deg,rgba(168,85,247,.1),rgba(168,85,247,.05));border-left:4px solid #a855f7;grid-column:1/-1\"><h3 style=\"color:#6b21a8\">💸 FINOPS</h3><div class=\"val\" style=\"color:#6b21a8\">"+esc(score_obj['domains'].get('finops',0))+"</div><div class=\"sub\">Otimização de custos (peso: 20%)</div></div>",
        "</div>",
        "</div>",
        "<div class=\"section\">",
        "<h2>� Busca Rápida</h2>",
        "<div class=\"search-box\">",
        "<input type=\"text\" id=\"globalSearch\" placeholder=\"Buscar por controle, recurso, domínio...\" />",
        "</div>",
        "</div>",
        "<div class=\"section\">",
        "<h2>⚠️ Top Recursos Vulneráveis</h2>",
        "<div id=\"top-vulnerable\">",
        _gerar_top_recursos_vulneraveis(findings),
        "</div>",
        "</div>",
        "<div class=\"section\">",
        "<h2>�📊 Resumo e Prioridades</h2>",
        "<div class=\"summary-box\" style=\"margin-bottom:24px\">",
        f"<p style=\"font-size:15px;line-height:1.8;margin-bottom:16px\">{esc(resumo)}</p>",
        "<div class=\"severity-strip\">",
    ]
    for label, cls in [("CRITICAL", "dot-critical"), ("HIGH", "dot-high"), ("MEDIUM", "dot-medium"), ("LOW", "dot-low"), ("INFO", "dot-info")]:
        if label in severidade:
            linhas.append(f"<span class='strip'><span class='dot {cls}'></span>{label} {esc(severidade.get(label))}</span>")
    linhas.extend([
        "</div>",
        "</div>",
        "<h3 style=\"margin-top:32px\">⚡ Top 5 Ações Recomendadas</h3>",
        "<table><thead><tr><th style=\"width:80px\">Sev.</th><th>Ação Recomendada</th><th style=\"width:140px\">Recurso</th><th>Remediação</th></tr></thead><tbody>",
    ])
    for f in top:
        recurso = f.resource
        if f.display_name:
            recurso = f"{recurso} (Name={f.display_name})"
        badge = sev_class.get(f.severity, "sev-info")
        linhas.append(
            "<tr>"
            f"<td><span class=\"badge {badge}\">{esc(f.severity)}</span></td>"
            f"<td><strong>{esc(f.title)}</strong></td>"
            f"<td><code style=\"background:#f1f5f9;padding:3px 6px;border-radius:4px;font-family:monospace;font-size:12px\">{esc(recurso)}</code></td>"
            f"<td>{esc(f.remediation)}</td>"
            "</tr>"
        )
    linhas.append("</tbody></table>")

    linhas.append("<div class=\"section\">")
    linhas.append("<h2>Análise por Domínio</h2>")
    linhas.append("<div class=\"domain-grid\">")
    for dominio_nome in ["iam", "security", "finops"]:
        itens = [f for f in findings if f.domain == dominio_nome]
        if not itens:
            continue
        linhas.append("<div style=\"background:#fff;border-radius:var(--radius);padding:20px;box-shadow:var(--shadow-sm);border:1px solid rgba(148,163,184,.12)\">")
        linhas.append(f"<h3 style=\"margin-top:0\">{esc(dominio_nome.upper())}</h3>")
        linhas.append(f"<p class=\"muted\">{len([f for f in findings if f.domain == dominio_nome])} achado(s) • {len(dominio_controles.get(dominio_nome, {}))} controle(s) únicos</p>")
        linhas.append("</div>")
    linhas.append("</div>")
    linhas.append("</div>")

    # Exceções (só mostrar se houver)
    if excecoes:
        linhas.append("<div class=\"section\">")
        linhas.append("<h2>✋ Exceções Aplicadas</h2>")
        linhas.append("<div class=\"list\"><ul>")
        for f in excecoes:
            linhas.append(f"<li><strong>{esc(f.control_id)}</strong> em <code style=\"background:#f1f5f9;padding:2px 4px;border-radius:3px;font-family:monospace;font-size:11px\">{esc(f.resource)}</code><br><span style=\"color:#6b7280;font-size:13px\">{esc(f.title)}</span></li>")
        linhas.append("</ul></div>")
        linhas.append("</div>")

    linhas.append("<div class=\"section\">")
    linhas.append("<h2>📊 Score de Maturidade AWS</h2>")
    linhas.append("<p class=\"muted\">Scores calculados automaticamente a partir dos achados. Penalidades: CRITICAL (-15), HIGH (-15), MEDIUM (-7), LOW (-3), INFO (0)</p>")
    linhas.append("<div style=\"display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:20px\">")
    
    # Domain scores with progress bars only
    for dom_label, dom_key in [("Segurança", "security"), ("IAM", "iam"), ("FinOps", "finops")]:
        score = score_obj['domains'].get(dom_key, 0)
        penalties = score_obj.get('penalties', {}).get(dom_key, [])
        total_penalty = sum(p['penalty'] for p in penalties)
        
        if score >= 80:
            status = "✅ Excelente"
        elif score >= 60:
            status = "⚠️ Bom"
        else:
            status = "❌ Atenção"
            
        linhas.append(f"<div class=\"score-display\">")
        linhas.append(f"<div style=\"flex:1\"><div class=\"score-label\">{dom_label} • {status}</div><div class=\"progress-bar\"><div class=\"progress-fill\" style=\"width:{score}%\"></div></div><div class=\"muted\" style=\"font-size:11px;margin-top:4px\">100 - {total_penalty} penalidade(s)</div></div>")
        linhas.append(f"<div class=\"score-val\">{score}</div>")
        linhas.append(f"</div>")
    
    linhas.append("</div>")
    
    # Score geral
    overall_score = score_obj['overall']
    if overall_score >= 80:
        status = "✅ Excelente"
    elif overall_score >= 60:
        status = "⚠️ Bom"
    else:
        status = "❌ Atenção"
    
    sec_score = score_obj['domains'].get('security', 0)
    iam_score = score_obj['domains'].get('iam', 0)
    fin_score = score_obj['domains'].get('finops', 0)
    
    linhas.append(f"<div style=\"background:linear-gradient(135deg,#f8fafc,#f1f5f9);border-radius:var(--radius);padding:24px;border-left:5px solid var(--brand);box-shadow:var(--shadow-sm);margin-top:20px\">")
    linhas.append(f"<div style=\"display:flex;justify-content:space-between;align-items:center\">")
    linhas.append(f"<div><h3 style=\"margin:0;font-size:16px\">Score Geral (Ponderado) {status}</h3><p class=\"muted\" style=\"margin:8px 0 0 0;font-size:13px\">({sec_score}×50%) + ({iam_score}×30%) + ({fin_score}×20%) = <strong>{overall_score}</strong></p></div>")
    linhas.append(f"<div style=\"font-size:48px;font-weight:950;background:linear-gradient(135deg,#0284c7,#6366f1);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text\">{overall_score}</div>")
    linhas.append(f"</div>")
    linhas.append("</div>")
    linhas.append("</div>")

    # Remover seção de observações FinOps duplicada
    if False:  # Desabilitado
        linhas.append("<div class=\"section\">")
        linhas.append("<h2>Observações FinOps</h2>")
        linhas.append("<p>Retenções de backup do RDS acima de 7 dias são tratadas como oportunidade de otimização de custos.</p>")
        linhas.append("</div>")

    if tag_recomendadas and tem_fin_001:
        linhas.append("<div class=\"section\">")
        linhas.append("<h2>Tags recomendadas</h2>")
        linhas.append(f"<p>Tags obrigatórias configuradas: {esc(', '.join(tag_recomendadas))}</p>")
        linhas.append("<p>Exemplo de valores: Owner=EquipeX, Environment=prod</p>")
        linhas.append("</div>")

    linhas.append("<div class=\"section\">")
    linhas.append("<h2>🔍 Detalhes Técnicos Completos</h2>")
    linhas.append("<p class=\"muted\" style=\"margin-bottom:20px\">Inventário completo de todos os achados identificados durante a auditoria. Clique nos filtros para visualizar por severidade.</p>")
    
    # Contador de severidades
    sev_counts = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    
    # Filtros de severidade
    linhas.append("<div style=\"display:flex;gap:10px;flex-wrap:wrap;margin-bottom:24px\">")
    linhas.append("<button class=\"filter-btn active\" data-filter=\"all\" style=\"padding:10px 18px;border-radius:24px;border:2px solid var(--brand);background:linear-gradient(135deg,var(--brand),var(--brand2));color:#fff;font-weight:800;font-size:13px;cursor:pointer;transition:var(--transition);box-shadow:var(--shadow-sm)\">Todos ("+str(total)+")</button>")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if sev in sev_counts:
            sev_badge = sev_class.get(sev, "sev-info")
            count = sev_counts[sev]
            linhas.append(f"<button class=\"filter-btn\" data-filter=\"{sev}\" style=\"padding:10px 18px;border-radius:24px;border:2px solid #e2e8f0;background:#fff;color:#475569;font-weight:800;font-size:13px;cursor:pointer;transition:var(--transition);box-shadow:var(--shadow-sm)\">{sev} ({count})</button>")
    linhas.append("</div>")
    
    # Tabela de detalhes
    linhas.append("<div class=\"details\" id=\"technical-details\">")
    linhas.append("<table style=\"font-size:14px\">")
    linhas.append("<thead><tr>")
    linhas.append("<th style=\"width:90px\">Severidade</th>")
    linhas.append("<th style=\"width:100px\">Controle</th>")
    linhas.append("<th style=\"width:120px\">Domínio</th>")
    linhas.append("<th>Recurso</th>")
    linhas.append("<th style=\"width:100px\">Região</th>")
    linhas.append("<th>Descrição do Achado</th>")
    linhas.append("</tr></thead>")
    linhas.append("<tbody>")
    
    for f in findings:
        reg = f.region or "global"
        dn = f" (Name={f.display_name})" if f.display_name else ""
        sev_badge = sev_class.get(f.severity, "sev-info")
        domain_upper = f.domain.upper()
        
        # Ícone por domínio
        domain_icon = {"SECURITY": "🛡️", "IAM": "🔐", "FINOPS": "💸", "GOVERNANCE": "📋"}.get(domain_upper, "📌")
        
        linhas.append(f"<tr data-severity=\"{esc(f.severity)}\">")
        linhas.append(f"<td><span class=\"badge {sev_badge}\">{esc(f.severity)}</span></td>")
        linhas.append(f"<td><code style=\"background:rgba(99,102,241,.08);padding:6px 10px;border-radius:8px;font-family:'JetBrains Mono','Fira Code',monospace;font-size:12px;font-weight:700;color:#4338ca;border:1px solid rgba(99,102,241,.2)\">{esc(f.control_id)}</code></td>")
        linhas.append(f"<td><span style=\"display:inline-flex;align-items:center;gap:6px;padding:6px 12px;background:linear-gradient(135deg,#f1f5f9,#e2e8f0);border-radius:20px;font-size:12px;font-weight:700;color:#1e293b\">{domain_icon} {esc(domain_upper)}</span></td>")
        linhas.append(f"<td><div style=\"max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap\" title=\"{esc(f.resource)}{esc(dn)}\"><code style=\"background:#f8fafc;padding:4px 8px;border-radius:6px;font-family:'JetBrains Mono','Fira Code',monospace;font-size:11px;color:#475569;border:1px solid #e2e8f0\">{esc(f.resource)}</code>{esc(dn)}</div></td>")
        linhas.append(f"<td><span style=\"padding:4px 10px;background:#f1f5f9;border-radius:12px;font-size:11px;font-weight:700;color:#64748b;border:1px solid #e2e8f0\">{esc(reg)}</span></td>")
        linhas.append(f"<td style=\"font-size:13px;color:#475569;line-height:1.6\">{esc(f.finding)}</td>")
        linhas.append("</tr>")
    
    linhas.append("</tbody></table>")
    linhas.append("</div>")
    
    # JavaScript para filtros e busca
    linhas.append("<script>")
    # Filtros de severidade
    linhas.append("document.querySelectorAll('.filter-btn').forEach(btn=>{")
    linhas.append("btn.addEventListener('click',()=>{")
    linhas.append("document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));")
    linhas.append("btn.classList.add('active');")
    linhas.append("const filter=btn.dataset.filter;")
    linhas.append("const rows=document.querySelectorAll('#technical-details tbody tr');")
    linhas.append("rows.forEach(row=>{")
    linhas.append("if(filter==='all'||row.dataset.severity===filter){")
    linhas.append("row.style.display='';")
    linhas.append("}else{")
    linhas.append("row.style.display='none';")
    linhas.append("}});")
    linhas.append("document.querySelectorAll('.filter-btn').forEach(b=>{")
    linhas.append("b.style.borderColor='#e2e8f0';")
    linhas.append("b.style.background='#fff';")
    linhas.append("b.style.color='#475569';")
    linhas.append("});")
    linhas.append("btn.style.borderColor='var(--brand)';")
    linhas.append("btn.style.background='linear-gradient(135deg,var(--brand),var(--brand2))';")
    linhas.append("btn.style.color='#fff';")
    linhas.append("});")
    linhas.append("});")
    # Busca global
    linhas.append("const searchInput=document.getElementById('globalSearch');")
    linhas.append("if(searchInput){")
    linhas.append("searchInput.addEventListener('input',e=>{")
    linhas.append("const term=e.target.value.toLowerCase();")
    linhas.append("const rows=document.querySelectorAll('#technical-details tbody tr');")
    linhas.append("rows.forEach(row=>{")
    linhas.append("const text=row.textContent.toLowerCase();")
    linhas.append("row.style.display=text.includes(term)?'':'none';")
    linhas.append("});")
    linhas.append("});")
    linhas.append("}")
    linhas.append("</script>")
    
    linhas.append("</div>")
    linhas.append("</div>")
    linhas.append("</body></html>")
    return "\n".join(linhas)


def _formatar_contagens(counter: Any) -> str:
    if not counter:
        return "sem dados"
    if hasattr(counter, "items"):
        ordem_sev = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        ordem_dom = ["security", "iam", "finops", "governance"]
        chaves = list(counter.keys())
        if all(k in ordem_sev for k in chaves):
            itens = [(k, counter.get(k)) for k in ordem_sev if k in counter]
        elif all(k in ordem_dom for k in chaves):
            itens = [(k, counter.get(k)) for k in ordem_dom if k in counter]
        else:
            itens = sorted(counter.items(), key=lambda kv: kv[0])
    else:
        return str(counter)
    return " • ".join(f"{k.upper()} {v}" for k, v in itens)


def compare_findings(atual: List[Finding], antigo: List[Dict[str, Any]]) -> Dict[str, List[Finding]]:
    def key_from_dict(d: Dict[str, Any]) -> Tuple[str, str, str | None]:
        return d.get("control_id"), d.get("resource"), d.get("region")

    atual_map = { (f.control_id, f.resource, f.region): f for f in atual }
    antigo_map = { key_from_dict(d): d for d in antigo }

    novos = [atual_map[k] for k in atual_map.keys() - antigo_map.keys()]
    resolvidos = [antigo_map[k] for k in antigo_map.keys() - atual_map.keys()]
    persistentes = [atual_map[k] for k in atual_map.keys() & antigo_map.keys()]

    return {"novos": novos, "resolvidos": resolvidos, "persistentes": persistentes}


def gerar_diff_markdown(ts: str, diff: Dict[str, List[Any]]) -> str:
    linhas = [
        f"# Comparativo de achados - {ts}",
        "",
        f"- Novos: {len(diff['novos'])}",
        f"- Resolvidos: {len(diff['resolvidos'])}",
        f"- Persistentes: {len(diff['persistentes'])}",
        "",
        "## Novos",
    ]
    for f in diff["novos"]:
        linhas.append(f"- {f.control_id} {f.resource} ({f.region or 'global'})")

    linhas.append("")
    linhas.append("## Resolvidos")
    for d in diff["resolvidos"]:
        linhas.append(f"- {d.get('control_id')} {d.get('resource')} ({d.get('region') or 'global'})")

    linhas.append("")
    linhas.append("## Persistentes")
    for f in diff["persistentes"]:
        linhas.append(f"- {f.control_id} {f.resource} ({f.region or 'global'})")

    return "\n".join(linhas)
