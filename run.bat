@echo off
title Network Security Scanner
cd /d "%~dp0"
echo Installing required libraries...
python -m pip install -r requirements.txt
if errorlevel 1 (
  echo.
  echo Python not found. Install Python 3.9+ and tick "Add Python to PATH".
  pause
  exit /b
)
echo.
echo Starting server at http://127.0.0.1:5000  (press Ctrl+C to stop)
start "" http://127.0.0.1:5000
python app.py
pause
