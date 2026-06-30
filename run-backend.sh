#!/bin/bash
cd backend
source venv/Scripts/activate
PYTHONPATH=. uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
