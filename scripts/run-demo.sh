#!/usr/bin/env bash
# One-command live demo for macOS or Linux.
#   ./scripts/run-demo.sh                   dev identity (tokens minted locally), scripted model
#   ./scripts/run-demo.sh --idp keycloak    real sign-in with Keycloak (needs Docker/Podman or Java 21)
#   ANTHROPIC_API_KEY=... ./scripts/run-demo.sh   also enables live Claude in the model menu
# Other options are passed through to `govagent demo-stack` (e.g. --port 8001 --keep-state).
#   ./scripts/run-demo.sh --traces jaeger  also export OpenTelemetry traces to Jaeger (needs Docker/Podman)
# KEEP_KEYCLOAK=1 / KEEP_JAEGER=1 leave those running when the demo stops.
set -euo pipefail
cd "$(dirname "$0")/.."

pick_python() {
  for p in python3.13 python3.12 python3.11 python3.10 python3; do
    if command -v "$p" >/dev/null 2>&1 && "$p" -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then
      echo "$p"; return 0
    fi
  done
  return 1
}

PY=$(pick_python) || {
  echo "Python 3.10+ is required. On macOS:  brew install python@3.12" >&2
  exit 1
}

if [ ! -x .venv/bin/python ]; then
  echo "Creating .venv with $PY"
  "$PY" -m venv .venv
fi

if ! .venv/bin/python -c 'import govagent.demo.app, govagent.orchestrator, opentelemetry.sdk, opentelemetry.exporter.otlp.proto.http' >/dev/null 2>&1; then
  echo "Installing the demo (one time)"
  .venv/bin/python -m pip install --quiet --upgrade pip
  .venv/bin/python -m pip install --quiet -e ".[demo]"
fi

if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  echo "ANTHROPIC_API_KEY found: 'Claude (live)' is available in the model menu."
else
  echo "No ANTHROPIC_API_KEY: scripted model only. Every scenario still runs against the real gateway."
fi

IDP="dev"
TRACES=""
ARGS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --idp) IDP="$2"; shift 2 ;;
    --idp=*) IDP="${1#--idp=}"; shift ;;
    --traces) TRACES="$2"; shift 2 ;;
    --traces=*) TRACES="${1#--traces=}"; shift ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

CLEANUP=()
cleanup() { for c in ${CLEANUP[@]+"${CLEANUP[@]}"}; do $c || true; done; }
trap cleanup EXIT

if [ "$TRACES" = "jaeger" ]; then
  if ./scripts/jaeger.sh start; then
    export OTEL_EXPORTER_OTLP_ENDPOINT="http://localhost:4318"
    export JAEGER_UI_URL="http://localhost:16686"
    export KC_TRACING=1
    [ -z "${KEEP_JAEGER:-}" ] && CLEANUP+=("./scripts/jaeger.sh stop")
  else
    echo "Continuing with the built-in trace view only."
  fi
fi

if [ "$IDP" = "keycloak" ]; then
  ./scripts/keycloak.sh start
  [ -z "${KEEP_KEYCLOAK:-}" ] && CLEANUP+=("./scripts/keycloak.sh stop")
  echo "Checking Keycloak against what the gateway expects..."
  if ! .venv/bin/govagent keycloak-check --report .demo/keycloak-check.txt; then
    echo "Keycloak self-test failed; details in .demo/keycloak-check.txt. Starting the demo anyway." >&2
  fi
  echo "Sign in as ana.ruiz, sam.okafor, lee.park, casey.morgan or riley.brooks (password: demo)."
  .venv/bin/govagent demo-stack --idp keycloak ${ARGS[@]+"${ARGS[@]}"}
else
  .venv/bin/govagent demo-stack ${ARGS[@]+"${ARGS[@]}"}
fi
