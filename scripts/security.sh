#!/usr/bin/env bash
set -euo pipefail

python -m pip install --upgrade pip
pip install -r requirements-dev.txt
pip install -r requirements.txt

ruff check .
bandit -r . -ll
pip-audit
trufflehog filesystem . --fail
