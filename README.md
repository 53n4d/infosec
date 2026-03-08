# infosec

## What's Inside
- Legacy CLI (`main.py`) for async IP range lookup, masscan hints, and CVE lookups.
- New FastAPI backend (`backend/api.py`) exposing the same capabilities as REST.
- React/Vite frontend (`frontend/`) with a cyber/infosec themed dashboard.

## Run the API
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.api:app --reload --port 8000
```

## Run the UI
```bash
cd frontend
npm install
npm run dev  # opens on http://localhost:5173
```

Set `VITE_API_BASE` in `frontend/.env` if your API is not on localhost:8000.
