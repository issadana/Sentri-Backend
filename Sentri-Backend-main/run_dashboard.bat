@echo off
REM Run the NOVA dashboard locally using the Anaconda main_env environment.
setlocal

set PYTHON="C:\Users\AbdallahKharoubi\anaconda3\envs\main_env\python.exe"
set PORT=5000

if not exist "%~dp0.env" (
    echo.
    echo ERROR: Missing .env file in Sentri-Backend-main\
    echo Copy .env.example to .env and set your remote DATABASE_URL.
    echo.
    exit /b 1
)

cd /d "%~dp0"
echo Starting NOVA dashboard on http://127.0.0.1:%PORT%
echo Using Python: %PYTHON%
%PYTHON% run.py
