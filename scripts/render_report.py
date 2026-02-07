from __future__ import annotations

import json
import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

from core.models import Finding
from core.reporting import enrich_findings, gerar_relatorio_html, gerar_relatorio_markdown


def load_findings(path: Path) -> list[Finding]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict) and "findings" in data:
        raw = data.get("findings", [])
        score = data.get("metadata", {}).get("score", {})
    else:
        raw = data
        score = {}
    findings = [Finding(**item) for item in raw]
    return findings, score


def main() -> None:
    if len(sys.argv) < 2:
        print("Uso: python3 scripts/render_report.py outputs/results-YYYYMMDD-HHMMSS.json")
        sys.exit(1)

    src = Path(sys.argv[1])
    if not src.exists():
        print("Arquivo não encontrado:", src)
        sys.exit(1)

    findings, score = load_findings(src)
    findings = enrich_findings(findings)

    ts = src.stem.replace("results-", "").replace("findings-", "")
    out_md = src.with_name(f"report-{ts}.md")
    out_html = src.with_name(f"report-{ts}.html")

    report_md = gerar_relatorio_markdown(findings, ts, [], score)
    out_md.write_text(report_md, encoding="utf-8")

    report_html = gerar_relatorio_html(findings, ts, [], score)
    out_html.write_text(report_html, encoding="utf-8")

    print("Relatórios atualizados:", out_md, out_html)


if __name__ == "__main__":
    main()
