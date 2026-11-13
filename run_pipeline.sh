#!/usr/bin/env bash
# Build everything, train, serve, run the verification suite, and leave the dashboard running.
#   ./run_pipeline.sh          # fresh run (models retrained), dashboard stays up
#   ./run_pipeline.sh --down   # tear everything down afterwards (CI)
# Exit code = the test suite's exit code.
set -uo pipefail
cd "$(dirname "$0")"
docker compose down -v --remove-orphans >/dev/null 2>&1
docker compose up -d --build || { echo "compose up failed"; docker compose logs --tail 50; exit 1; }
rc=$(docker wait "$(docker compose ps -aq tests)")
docker compose logs --no-log-prefix tests | grep -E "PASSED|FAILED|ERROR|SKIPPED| passed| failed" || true
echo "test suite exit code: $rc"
if [[ "${1:-}" == "--down" ]]; then
  docker compose down --remove-orphans >/dev/null 2>&1
else
  echo "dashboard: http://127.0.0.1:${DASHBOARD_PORT:-8501}   (stop with: docker compose down)"
fi
exit "$rc"
