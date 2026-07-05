@echo off
REM Utility scripts for the NOVA dashboard (Anaconda main_env).
setlocal
set PYTHON=C:\Users\AbdallahKharoubi\anaconda3\envs\main_env\python.exe
cd /d "%~dp0.."

if "%1"=="list-admins" (
    %PYTHON% scripts\list_admins.py
    exit /b %ERRORLEVEL%
)

if "%1"=="create-admin" (
    shift
    %PYTHON% scripts\create_admin.py %*
    exit /b %ERRORLEVEL%
)

echo Usage:
echo   scripts\run_with_env.bat list-admins
echo   scripts\run_with_env.bat create-admin --email you@example.com --username admin --password yourpass
exit /b 1
