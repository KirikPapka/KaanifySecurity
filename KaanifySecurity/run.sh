
set -euo pipefail
cd "$(dirname "$0")"

source ../venv/bin/activate
uvicorn server.server:app --host 0.0.0.0 --port 5050 --reload