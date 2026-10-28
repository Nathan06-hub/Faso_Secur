@echo off
title FASO-SECUR — Demarrage Souverain Local (Backend FastAPI + Frontend React)
echo ============================================================================
echo   FASO-SECUR — Messagerie Souveraine de l'Administration (Burkina Faso)
echo   Demarrage du serveur FastAPI (Port 8000) et du client React (Port 5173)...
echo ============================================================================

start "FASO-SECUR Backend (FastAPI)" cmd /k "cd backend && python -m uvicorn main:app --host 127.0.0.1 --port 8000"
start "FASO-SECUR Frontend (React Vite)" cmd /k "cd frontend && npm install && npm run dev"

echo.
echo -> Backend API & Docs : http://127.0.0.1:8000/docs
echo -> Interface Web E2EE : http://localhost:5173
pause
