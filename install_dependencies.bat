@echo off
REM University Portal - Automatic Dependency Installer
REM This script installs all required dependencies

echo.
echo ===============================================
echo University Portal - Dependency Installer
echo ===============================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python from https://www.python.org/
    pause
    exit /b 1
)

echo Python is installed. Proceeding with dependency installation...
echo.

REM Upgrade pip to latest version
echo Upgrading pip...
python -m pip install --upgrade pip
if %errorlevel% neq 0 (
    echo Warning: Could not upgrade pip
)

echo.
echo Installing dependencies from requirements.txt...
python -m pip install -r requirements.txt

if %errorlevel% equ 0 (
    echo.
    echo ===============================================
    echo SUCCESS: All dependencies installed!
    echo This project uses Python standard library only.
    echo ===============================================
    echo.
) else (
    echo.
    echo ERROR: Failed to install dependencies
    echo.
    pause
    exit /b 1
)

pause
