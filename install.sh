#!/usr/bin/env bash
# Nasi Lemak gateway installer for Ubuntu 24.04 amd64.
#
# This script bootstraps an existing Ubuntu 24.04 system with Docker (if
# missing), generates local credentials, provisions PostgreSQL roles and starts
# the gateway stack. It does not install or replace the operating system.
#
# Run as root for mutating operations:
#
#   sudo bash ./install.sh
#
# Use --check or --plan to inspect requirements and planned actions without
# making changes. The Python installer does the real work; this shell wrapper
# only validates the execution environment.
#
# The checkout root containing this script is used as --project-dir, so the
# installer works regardless of the caller's current directory. Pass an
# explicit --project-dir (or --project-dir=...) to override that location.

set -euo pipefail

readonly=false
project_dir_set=false
for arg in "$@"; do
  case "$arg" in
    --check|--plan) readonly=true ;;
    --project-dir|--project-dir=*) project_dir_set=true ;;
  esac
done

if [[ "$readonly" != "true" && "${EUID:-}" != "0" ]]; then
  echo "This installer must run as root for mutating operations." >&2
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "Missing required command: python3" >&2
  echo "Install python3 with your system package manager or an approved bootstrap before running the installer." >&2
  exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ "$project_dir_set" == "true" ]]; then
  exec python3 "$SCRIPT_DIR/scripts/install.py" "$@"
fi
exec python3 "$SCRIPT_DIR/scripts/install.py" --project-dir "$SCRIPT_DIR" "$@"
