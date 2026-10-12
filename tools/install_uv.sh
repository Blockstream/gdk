#! /usr/bin/env bash
# Install the pinned uv into its own venv, so no system Python is modified.
set -e

python=${1:-python3}
"$python" -m venv /opt/uv
/opt/uv/bin/pip install --disable-pip-version-check --require-hashes -r "$(dirname "$0")/requirements-uv.txt"
ln -sf /opt/uv/bin/uv /usr/local/bin/uv
