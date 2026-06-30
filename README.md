# Conseal Correction Review Tool

**Sprintfour Hackathon - Problem 3: Fixing the Tool's Mistakes**

A correction review interface that makes dangerous PII exposures impossible to miss, while keeping routine redaction reviews fast.

## The Problem

Sam reviews AI-suggested redactions. The tool makes two kinds of mistakes:
- **False positives** (harmless text redacted) — annoying, low cost
- **False negatives** (real PII left exposed) — dangerous, high cost

Traditional review UIs treat these errors the same way, so Sam skims past both. This tool applies asymmetric friction: dangerous misses require deliberate action, routine approvals stay fast.

## Quick Start

**1. Start the backend:**
```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows CMD
pip install -r requirements.txt
python -m app.seed             # Create sample document
uvicorn app.main:app --reload
```

**2. Start the frontend:**
```bash
cd frontend
npm install
npm run dev
```

**3. Open http://localhost:5173**

## Reset to Clean State

The backend database (`conseal_review.db`) persists between restarts. To get a fresh state:

**Backend (reseed database):**
```bash
cd backend
python -m app.seed
```

**Frontend (clear Vite cache):**
```bash
cd frontend
rmdir /s /q node_modules\.vite   # Windows CMD
# or: rm -rf node_modules/.vite  # Git Bash
npm run dev
```

## Architecture

- **Backend:** FastAPI + SQLite
- **Frontend:** React + TypeScript + Vite
- **Risk Scorer:** Regex-based second-pass scanner that catches PII the detector missed

## Key Features

### Visual Risk Hierarchy
- **Critical (red):** Phone numbers, SSNs the detector missed
- **Elevated (orange):** Names, emails the detector missed
- **Standard (gray):** Routine proposed redactions

### Two-Step Dismissal
Dismissing a flagged risk requires two clicks (stage → confirm), adding friction to dangerous decisions while keeping safe actions fast.

### Risk-Framed Summary
Completion shows "exposures caught" and "exposures missed" — not just accuracy percentages.

## Demo Document

A debt collection demand letter with:
- 8 ground truth PII items
- 5 correct redactions (detector got right)
- 4 over-redactions (detector false positives)
- 3 missed PII (detector false negatives, caught by risk scorer)
- 1 decoy (case reference number that looks like a phone)

## License

MIT
