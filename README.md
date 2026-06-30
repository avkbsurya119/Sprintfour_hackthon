<div align="center">
  
# 🛡️ Conseal: Correction Review Tool
  
**Sprintfour Hackathon - Problem 3: Fixing the Tool's Mistakes**

*A smart, friction-based correction review interface that makes dangerous PII exposures impossible to miss, while keeping routine redaction reviews lightning fast.*

[![React](https://img.shields.io/badge/React-20232A?style=for-the-badge&logo=react&logoColor=61DAFB)](https://reactjs.org/)
[![Vite](https://img.shields.io/badge/Vite-B73BFE?style=for-the-badge&logo=vite&logoColor=FFD62E)](https://vitejs.dev/)
[![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=for-the-badge&logo=fastapi)](https://fastapi.tiangolo.com/)
[![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)

</div>

---

## 🎯 The Problem

Sam reviews AI-suggested redactions daily. Standard detection tools make two kinds of mistakes:
- ❌ **False Positives:** Harmless text is redacted (Annoying, but low cost)
- 🚨 **False Negatives:** Real PII is left exposed (Dangerous, high cost)

Traditional review UIs treat these errors the exact same way. This causes reviewers to skim past both. **Conseal** applies **asymmetric friction**: dangerous misses require deliberate, multi-step actions to dismiss, while routine approvals stay incredibly fast.

---

## ✨ Key Features

### 🎨 Premium Review Interface
- **Interactive Landing Page:** Incorporates a beautiful, interactive 3D WebGL Ribbons background powered by React Bits & OGL, styled with a modern *Ice Latte & Mint* color palette.
- **Visual Risk Hierarchy:** 
  - 🔴 **Critical:** Phone numbers and SSNs the detector missed.
  - 🟠 **Elevated:** Names and emails the detector missed.
  - ⚪ **Standard:** Routine proposed redactions.
- **Inline Unredact & Reset All:** Quickly fix mistakes with inline resets on every card, or instantly revert the entire document's decisions with a single "Reset All" button.

### 🛡️ Two-Step Dismissal
Dismissing a flagged risk requires two clicks (Stage → Confirm). This adds deliberate friction to potentially dangerous decisions while keeping safe actions fast.

### 🧠 Enhanced Edge-Case Detection
Upgraded regex rules specifically target edge cases that standard ML models (like spaCy or Presidio) often miss:
- Malformed emails lacking TLDs (e.g., `user@company`)
- ALL CAPS Indian names and locations
- Unstructured usernames and percentages

---

## 🚀 Quick Start

Get the app running locally in seconds.

### 1. Start the Backend (FastAPI)
```bash
cd backend
python -m venv venv
venv\Scripts\activate          # Windows CMD
# source venv/bin/activate     # Mac/Linux
pip install -r requirements.txt
python -m app.seed             # Create sample document
uvicorn app.main:app --reload
```

### 2. Start the Frontend (Vite + React)
```bash
cd frontend
npm install
npm run dev
```

### 3. Open the App
Navigate to [http://localhost:5173](http://localhost:5173) in your browser! 🎉

---

## ♻️ Resetting the State

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
# rm -rf node_modules/.vite      # Git Bash / Mac / Linux
npm run dev
```

---

## 🏗️ Architecture

- **Backend:** FastAPI + SQLite (Zero-config persistence)
- **Frontend:** React + TypeScript + Vite (Lightning fast HMR)
- **Risk Scorer:** An ensemble system (spaCy + Presidio + Custom Regex) that acts as a second-pass scanner to catch PII the standard detector missed.

---

## 📄 The Demo Document

Try out the built-in demo document! It's a debt collection demand letter strategically seeded with:
- **8** ground truth PII items
- **5** correct redactions (detector got right)
- **4** over-redactions (detector false positives)
- **3** missed PII (detector false negatives, caught by the risk scorer)
- **1** decoy (a case reference number that looks like a phone number)

---

<div align="center">
  <i>Built with ❤️ for the Sprintfour Hackathon</i>
</div>
