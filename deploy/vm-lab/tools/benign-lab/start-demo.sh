#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"
if [ ! -x .venv/bin/benign-lab ]; then
  echo 'Primero sigue la instalación en README.md para crear .venv.' >&2
  exit 1
fi
exec .venv/bin/benign-lab serve --lab config/lab.demo.yaml "$@"
