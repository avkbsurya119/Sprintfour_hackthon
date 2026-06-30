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
- **Visual Risk Hierarchy:** PII detections are strictly grouped by threat level.
  - **Critical (Red):** Severe misses like phone numbers and SSNs.
  - **Elevated (Orange):** Moderate misses like names and emails.
  - **Standard (Gray):** Routine, high-confidence proposed redactions.
- **Two-Step Dismissal Mechanism:** Dismissing a flagged potential risk requires two clicks (Stage to dismiss, then Confirm). This deliberate friction forces the reviewer to pause on potentially dangerous decisions while keeping safe actions fast.
- **Critical Risk Pulse Animation:** Undecided critical risk flags feature a subtle pulse animation on their box-shadow to draw immediate attention without being overwhelming.
- **Enhanced Urgency Borders:** Critical and elevated risk flags feature left accent borders (5px and 4px respectively) to create a strong visual hierarchy in the sidebar list.
- **Risk-Framed Summary Modal:** Upon completion, the reviewer is presented with "exposures caught" and "exposures missed" rather than a gamified accuracy percentage, reinforcing a security-first mindset.

### Advanced Workflow Mechanics
- **Scroll-to-Sidebar Navigation:** Clicking a highlighted span directly within the document viewer automatically scrolls and focuses the corresponding action card in the sidebar.
- **Collapsed Single-Line Decided View:** Once a decision is made, the full review card collapses into a compact single-line view showing just the text and a decision badge, reducing visual noise.
- **Per-Item Submission State:** Double-click protection is implemented on a per-item basis. This allows reviewers to perform parallel submissions rapidly without locking the entire UI globally.
- **Smart Deduplication:** Repeated instances of the exact same PII string are grouped together. A single reviewer decision automatically propagates to all identical occurrences in the document.
- **Inline Corrections & Global Reset:** Every decided card features an inline "Reset" button, allowing users to immediately undo a mistaken click. A global "Reset All" master switch is also available for a clean slate.

### Advanced Detection & Edge-Case Handling
- **Confidence-Tier Split System:** Detections are dynamically categorized. High-confidence structural patterns (e.g., SSN, Email) are routed to "Proposed Redactions," while lower-confidence heuristics (e.g., capitalized name pairs) are routed to "Potential Risks."
- **Ensemble Detection System:** The backend utilizes a robust ensemble approach combining spaCy NER, Microsoft Presidio, and highly specialized Regex fallbacks for maximum coverage.
- **Enhanced OCR Anomaly Recognition:** Upgraded rule sets specifically target edge cases that standard ML models struggle with, including:
  - Malformed emails lacking TLDs (e.g., `user@company`).
  - ALL CAPS strings often parsed incorrectly (e.g., Indian names and locations).
  - Unstructured usernames, alphanumeric IDs, and isolated percentages.
- **Multi-Format Processing:** Full backend support for parsing and detecting PII within uploaded PDF, DOCX, and TXT files.
- **Manual Span Tagging:** Reviewers can freely highlight any unflagged text in the document viewer and manually assign it a PII category on the fly.

### Premium Interface
- **Modern WebGL Landing Page:** Incorporates a beautiful, interactive 3D WebGL Ribbons background (powered by React Bits & OGL) combined with a premium Ice Latte and Mint color palette for a sophisticated product feel.
- **Styled Plain Text Rendering:** Documents are rendered with deliberate typography (font, line-height, padding) to look professional without the unnecessary complexity of rich text layout engines.

---

## The Demo Document Design

The built-in demo document is a fabricated debt collection demand letter strategically seeded to demonstrate real-world failure modes:
- **Position-Based Misses:** Standard detectors reliably catch recipient details in the header, but often miss sender info buried in the signature block. The demo simulates this exactly.
- **Contextually Labeled Decoys:** A case reference number deliberately mimicking a phone number structure tests the reviewer's judgment against pure pattern recognition.
- **Balanced Workload:** Contains 8 ground truth items, 5 correct redactions, 4 over-redactions, 3 missed PII fields, and 1 decoy, allowing a full walkthrough of all UX features in under 3 minutes.

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

<div align="center">
  <i>Built for the Sprintfour Hackathon</i>
</div>
