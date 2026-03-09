# XSEVERITY Recon Console

Full-stack recon tool for pulling IPv4 ranges, running/watching scans, grabbing banners/CVEs, and visualizing results.

## Stack
- **Backend:** FastAPI (`backend/api.py`), async tasks, SSE streams for scan status/hits.
- **Frontend:** React + Vite (`frontend/`), mono/cyber UI, GeoMap modal, inline IP detail pages.
- **Extras:** Legacy CLI (`main.py`) for quick range/CVE lookups.

## Features
- Country range pull (all RIRs) with optional cache bypass.
- Scan console: preset/custom/all ports, wide/deep modes, CVE lookup toggle, stat counters.
- Hit filters: port/service search, severity (High/Critical), selection + re-scan, CSV/JSON export.
- HTTP helpers: title + screenshot capture (Playwright) shown on IP detail.
- GeoMap modal: plots up to 200 hosts with country/ISP/port info and sidebar search.

## Prereqs
- Python 3.12+, Node 18+.
- Playwright Chromium (for screenshots): `pip install playwright` then `playwright install chromium` inside the backend venv.

## Backend setup
```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn backend.api:app --reload --port 8000
```

## Frontend setup
```bash
cd frontend
npm install
# set API base if different
echo "VITE_API_BASE=http://localhost:8000" > .env
npm run dev   # http://localhost:5173
```

## Notes
- Builds: `npm run build` (frontend) and standard UVicorn for backend.
- Screenshots require Playwright; without it, `/http/screenshot` returns an error message.
- Local artifacts: `frontend/src/firebase.js` is ignored; keep secrets out of git.
