#!/usr/bin/env bash
# Start or stop Jaeger v2 (all-in-one) for the demo's OpenTelemetry traces. Needs Docker or Podman.
#   ./scripts/jaeger.sh start    UI http://localhost:16686, OTLP gRPC :4317, OTLP HTTP :4318
#   ./scripts/jaeger.sh stop
set -euo pipefail
JAEGER_VERSION="${JAEGER_VERSION:-2.21.0}"
NAME="govagent-jaeger"
NET="govagent"

engine() {
  for e in docker podman; do
    if command -v "$e" >/dev/null 2>&1 && "$e" info >/dev/null 2>&1; then echo "$e"; return 0; fi
  done
  return 1
}

case "${1:-start}" in
  start)
    if curl -fsS http://localhost:16686 >/dev/null 2>&1; then echo "Jaeger already running: http://localhost:16686"; exit 0; fi
    E="$(engine)" || { echo "Jaeger needs Docker or Podman running. The built-in trace view works without it." >&2; exit 1; }
    "$E" network inspect "$NET" >/dev/null 2>&1 || "$E" network create "$NET" >/dev/null
    "$E" rm -f "$NAME" >/dev/null 2>&1 || true
    echo "Starting Jaeger ${JAEGER_VERSION} with ${E}"
    for image in "cr.jaegertracing.io/jaegertracing/jaeger:${JAEGER_VERSION}" "docker.io/jaegertracing/jaeger:${JAEGER_VERSION}"; do
      if "$E" run -d --name "$NAME" --network "$NET" -p 16686:16686 -p 4317:4317 -p 4318:4318 "$image" >/dev/null 2>&1; then
        break
      fi
      "$E" rm -f "$NAME" >/dev/null 2>&1 || true
    done
    for _ in $(seq 1 30); do
      if curl -fsS http://localhost:16686 >/dev/null 2>&1; then echo "Jaeger ready: http://localhost:16686"; exit 0; fi
      sleep 1
    done
    echo "Jaeger did not start (try: $E logs $NAME)" >&2; exit 1 ;;
  stop)
    for e in docker podman; do command -v "$e" >/dev/null 2>&1 && "$e" rm -f "$NAME" >/dev/null 2>&1 || true; done
    echo "Jaeger stopped." ;;
  *) echo "usage: $0 start|stop" >&2; exit 2 ;;
esac
