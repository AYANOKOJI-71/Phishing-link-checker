#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHONPATH="$REPO_ROOT" python -m unittest discover -s "$REPO_ROOT/tests"
