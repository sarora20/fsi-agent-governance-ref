#!/usr/bin/env bash
# Start or stop a local Keycloak for the demo, with the fsi-demo realm imported.
#   ./scripts/keycloak.sh start     Docker/Podman if running, else the Keycloak download on Java 21
#   ./scripts/keycloak.sh stop
#   ./scripts/keycloak.sh status
# Keycloak listens on http://localhost:8180; admin console login admin / admin (local demo only).
set -euo pipefail
cd "$(dirname "$0")/.."

KC_VERSION="${KC_VERSION:-26.7.4}"
KC_PORT="${KC_PORT:-8180}"
NAME="govagent-keycloak"
ISSUER="http://localhost:${KC_PORT}/realms/fsi-demo"
DIST_DIR=".keycloak"
LOG="${DIST_DIR}/keycloak.log"
PIDFILE="${DIST_DIR}/keycloak.pid"

engine() {
  for e in docker podman; do
    if command -v "$e" >/dev/null 2>&1 && "$e" info >/dev/null 2>&1; then echo "$e"; return 0; fi
  done
  return 1
}

java21() {
  local j=""
  if [ -x /usr/libexec/java_home ]; then j="$(/usr/libexec/java_home -v 21+ 2>/dev/null || true)"; fi
  if [ -n "$j" ]; then echo "$j/bin/java"; return 0; fi
  if command -v java >/dev/null 2>&1; then
    local v; v="$(java -version 2>&1 | awk -F'"' '/version/ {print $2}' | cut -d. -f1)"
    if [ "${v:-0}" -ge 21 ] 2>/dev/null; then command -v java; return 0; fi
  fi
  return 1
}

wait_ready() {
  printf "Waiting for Keycloak"
  for _ in $(seq 1 120); do
    if curl -fsS "${ISSUER}/.well-known/openid-configuration" >/dev/null 2>&1; then echo " ready."; return 0; fi
    printf "."; sleep 2
  done
  echo; echo "Keycloak did not become ready. See: ${LOG} (or: docker logs ${NAME})" >&2
  return 1
}

start() {
  if curl -fsS "${ISSUER}/.well-known/openid-configuration" >/dev/null 2>&1; then
    echo "Keycloak already running at ${ISSUER}"; return 0
  fi
  mkdir -p "$DIST_DIR"
  if E="$(engine)"; then
    echo "Starting Keycloak ${KC_VERSION} with ${E} (first run downloads the image)"
    "$E" rm -f "$NAME" >/dev/null 2>&1 || true
    TRACING=()
    NETWORK=()
    if [ -n "${KC_TRACING:-}" ]; then   # send Keycloak's own spans to Jaeger (same trace as the demo)
      "$E" network inspect govagent >/dev/null 2>&1 || "$E" network create govagent >/dev/null
      NETWORK=(--network govagent)
      TRACING=(--tracing-enabled=true --tracing-endpoint=http://govagent-jaeger:4317 --telemetry-service-name=keycloak)
    fi
    "$E" run -d --name "$NAME" ${NETWORK[@]+"${NETWORK[@]}"} -p "${KC_PORT}:8080" \
      -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
      -v "$PWD/keycloak:/opt/keycloak/data/import:ro" \
      "quay.io/keycloak/keycloak:${KC_VERSION}" \
      start-dev --import-realm --hostname="http://localhost:${KC_PORT}" ${TRACING[@]+"${TRACING[@]}"} >/dev/null
    echo "$E" > "${DIST_DIR}/engine"
  else
    JAVA="$(java21)" || {
      echo "Keycloak needs Docker (or Podman) running, or Java 21+." >&2
      echo "  Docker Desktop: https://www.docker.com/products/docker-desktop/" >&2
      echo "  or Java:        brew install openjdk@21" >&2
      exit 1
    }
    local home="${DIST_DIR}/keycloak-${KC_VERSION}"
    if [ ! -x "${home}/bin/kc.sh" ]; then
      echo "Downloading Keycloak ${KC_VERSION} (about 200 MB, one time)"
      curl -fL --progress-bar -o "${DIST_DIR}/kc.tar.gz" \
        "https://github.com/keycloak/keycloak/releases/download/${KC_VERSION}/keycloak-${KC_VERSION}.tar.gz"
      tar -xzf "${DIST_DIR}/kc.tar.gz" -C "$DIST_DIR"
      rm -f "${DIST_DIR}/kc.tar.gz"
    fi
    rm -rf "${home}/data/h2"   # fresh realm from the file on every start
    mkdir -p "${home}/data/import"
    cp keycloak/realm-fsi-demo.json "${home}/data/import/"
    echo "Starting Keycloak ${KC_VERSION} on Java ($JAVA)"
    TRACING=()
    if [ -n "${KC_TRACING:-}" ]; then
      TRACING=(--tracing-enabled=true --tracing-endpoint=http://localhost:4317 --telemetry-service-name=keycloak)
    fi
    JAVA_HOME="$(dirname "$(dirname "$JAVA")")" KC_BOOTSTRAP_ADMIN_USERNAME=admin KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
      nohup "${home}/bin/kc.sh" start-dev --http-port "${KC_PORT}" --import-realm \
      --hostname="http://localhost:${KC_PORT}" ${TRACING[@]+"${TRACING[@]}"} > "$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    echo "java" > "${DIST_DIR}/engine"
  fi
  wait_ready
}

stop() {
  local how; how="$(cat "${DIST_DIR}/engine" 2>/dev/null || true)"
  case "$how" in
    docker|podman) "$how" rm -f "$NAME" >/dev/null 2>&1 || true ;;
    java) [ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null || true ;;
  esac
  rm -f "${DIST_DIR}/engine" "$PIDFILE"
  echo "Keycloak stopped."
}

case "${1:-start}" in
  start) start ;;
  stop) stop ;;
  status) curl -fsS "${ISSUER}/.well-known/openid-configuration" >/dev/null 2>&1 \
            && echo "running: ${ISSUER}" || { echo "not running"; exit 1; } ;;
  *) echo "usage: $0 start|stop|status" >&2; exit 2 ;;
esac
