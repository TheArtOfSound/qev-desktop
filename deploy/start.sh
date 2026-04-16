#!/usr/bin/env bash
set -euo pipefail

echo "Starting BRY-NFET-SX..."

# Start FastAPI in background
uv run fastapi run src/bry_nfet_sx/api/app.py --port 8001 --host 0.0.0.0 &
API_PID=$!

# Start Streamlit with baseUrlPath for reverse proxy at /app/
uv run streamlit run dashboard/streamlit_app.py \
  --server.port 8506 \
  --server.address 0.0.0.0 \
  --server.headless true \
  --server.baseUrlPath /app \
  --browser.gatherUsageStats false &
UI_PID=$!

echo "  API:       http://0.0.0.0:8001"
echo "  Dashboard: http://0.0.0.0:8506/app/"

wait -n $API_PID $UI_PID
