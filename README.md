<div align="center">
  
# Conseal: Correction Review Tool
  
**Sprintfour Hackathon - Problem 3: Fixing the Tool's Mistakes**

*A smart, friction-based correction review interface that makes dangerous PII exposures impossible to miss, while keeping routine redaction reviews highly efficient.*

[![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://reactjs.org/)
[![Vite](https://img.shields.io/badge/Vite-B73BFE?style=for-the-badge&logo=vite&logoColor=FFD62E)](https://vitejs.dev/)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)

</div>

---

## The Problem

Reviewers analyze AI-suggested redactions daily. Standard detection tools typically make two kinds of mistakes:
- **False Positives:** Harmless text is redacted (low cost, merely inconvenient).
- **False Negatives:** Real PII is left exposed (high cost, severe data risk).

Traditional review interfaces treat these errors with the exact same UX priority, leading reviewers to inevitably skim past both. **Conseal** introduces **asymmetric friction**: dismissing a dangerous omission requires deliberate, multi-step action, while approving routine redactions remains lightning fast.

---

## Comprehensive Feature List

### Core UX & "Asymmetric Friction"
- **Visual Risk Hierarchy:** PII detections are strictly grouped by threat level:
  - **Critical (Red):** Severe misses like phone numbers and SSNs.
  - **Elevated (Orange):** Moderate misses like names and emails.
  - **Standard (Gray):** Routine, high-confidence proposed redactions.
- **Two-Step Dismissal Mechanism:** Dismissing a flagged potential risk requires two clicks (Stage to dismiss, then Confirm). This deliberate friction forces the reviewer to pause on potentially dangerous decisions while keeping safe actions fast.
- **Risk-Framed Summary Modal:** Upon completion, the reviewer is presented with "exposures caught" and "exposures missed" rather than a gamified accuracy percentage, reinforcing a security-first mindset.

### Advanced Detection & Edge-Case Handling
- **Ensemble Detection System:** The backend utilizes an ensemble approach combining spaCy NER, Microsoft Presidio, and highly specialized Regex fallbacks for maximum coverage.
- **Enhanced OCR Anomaly Recognition:** Upgraded rule sets specifically target edge cases that standard ML models struggle with, including:
  - Malformed emails lacking TLDs (e.g., `user@company`).
  - ALL CAPS strings often parsed incorrectly (e.g., Indian names and locations).
  - Unstructured usernames, alphanumeric IDs, and isolated percentages.
- **Smart Deduplication:** Repeated instances of the exact same PII string are grouped together. A single reviewer decision automatically propagates to all identical occurrences in the document.

### Premium Interface & Usability
- **Modern Landing Page UI:** Incorporates an interactive 3D WebGL Ribbons background (powered by React Bits & OGL) combined with a premium Ice Latte and Mint color palette for a sophisticated product feel.
- **Inline Corrections:** Every decided card features an inline "Reset" button, allowing users to immediately undo a mistaken click without relying on a rigid chronological undo stack.
- **Global Reset All:** A master reset function with a safety confirmation prompt allows reviewers to revert all decisions in the document if they need to rethink their redaction strategy.
- **Manual Span Tagging:** Reviewers can freely highlight any unflagged text in the document viewer and manually assign it a PII category on the fly.
- **Multi-Format Processing:** Full backend support for parsing and detecting PII within uploaded PDF, DOCX, and TXT files.

---

## Quick Start Guide

Deploy the application locally with the following steps.

### 1. Start the Backend (FastAPI)
```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows CMD
# source venv/bin/activate     # Mac/Linux
pip install -r requirements.txt
python -m app.seed             # Create sample document database
uvicorn app.main:app --reload
```

### 2. Start the Frontend (Vite + React)
```bash
cd frontend
npm install
npm run dev
```

### 3. Open the Application
Navigate to [http://localhost:5173](http://localhost:5173) in your web browser.

---

## Resetting the Application State

The backend database (`conseal_review.db`) persists between restarts. To force a completely fresh state:

**Backend (reseed database):**
```bash
cd backend
python -m app.seed
```

**Frontend (clear Vite cache):**
```bash
cd frontend
rmdir /s /q node_modules\.vite   # Windows CMD
# rm -rf node_modules/.vite      # Git Bash / Mac / Linux
npm run dev
```

---

## Architecture Overview

- **Backend:** FastAPI + SQLite (Zero-configuration persistence)
- **Frontend:** React + TypeScript + Vite (Optimized for speed and HMR)
- **Risk Scorer:** A multi-layered detection pipeline designed to act as a second-pass scanner, specifically catching PII that the primary detection pass missed.

---

## The Demo Document

You can try out the built-in demo document upon launching the app. It is a fabricated debt collection demand letter strategically seeded with:
- **8** ground truth PII items
- **5** correct redactions (the detector succeeded)
- **4** over-redactions (the detector threw a false positive)
- **3** missed PII fields (detector false negatives, accurately caught by the risk scorer)
- **1** decoy item (a case reference number deliberately mimicking a phone number structure)

---

<div align="center">
  <i>Built for the Sprintfour Hackathon</i>
</div>
