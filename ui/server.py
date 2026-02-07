from __future__ import annotations

import html
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import unquote

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUTS_DIR = BASE_DIR / "outputs"
HOST = "127.0.0.1"
PORT = 8765


def _list_reports() -> list[Path]:
    if not OUTPUTS_DIR.exists():
        return []
    files = sorted(OUTPUTS_DIR.glob("report-*.html"), reverse=True)
    return files


class ReportHandler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: str, content_type: str = "text/html; charset=utf-8") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def do_GET(self) -> None:
        path = unquote(self.path)
        if path == "/" or path == "/index.html":
            reports = _list_reports()
            items = "".join(
                f"<li><a href='/report/{html.escape(p.name)}'>{html.escape(p.name)}</a></li>" for p in reports
            )
            body = f"""
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Relatórios AWS Audit MVP</title>
  <style>
    body{{font-family:Arial,Helvetica,sans-serif;margin:24px;background:#f3f4f6;color:#0b1220}}
    h1{{margin:0 0 12px}}
    .card{{background:#fff;border-radius:10px;padding:16px;box-shadow:0 6px 18px rgba(0,0,0,.08)}}
    ul{{margin:8px 0 0 18px}}
    a{{color:#2563eb;text-decoration:none}}
  </style>
</head>
<body>
  <div class="card">
    <h1>Relatórios AWS Audit MVP</h1>
    <p>Escolha um relatório para abrir:</p>
    <ul>{items if items else '<li>Nenhum relatório encontrado em outputs/</li>'}</ul>
  </div>
</body>
</html>
"""
            self._send(200, body)
            return

        if path.startswith("/report/"):
            name = path.replace("/report/", "")
            target = OUTPUTS_DIR / name
            if not target.exists() or target.suffix != ".html":
                self._send(404, "Relatório não encontrado.")
                return
            data = target.read_text(encoding="utf-8")
            self._send(200, data)
            return

        self._send(404, "Página não encontrada.")


def main() -> None:
    server = HTTPServer((HOST, PORT), ReportHandler)
    print(f"Servidor local iniciado em http://{HOST}:{PORT}")
    print("Use Ctrl+C para encerrar.")
    server.serve_forever()


if __name__ == "__main__":
    main()
