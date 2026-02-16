@echo off
REM Quick start script for Phishing Detection System on Windows

echo.
echo ========================================
echo Phishing Detection System - Quick Start
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.8 or higher from python.org
    echo.
    pause
    exit /b 1
)

echo Step 1: Checking Python installation...
python --version
echo ✓ Python found
echo.

echo Step 2: Installing dependencies...
echo Installing required packages...
pip install -r Backend\requirements.txt
if errorlevel 1 (
    echo Error: Failed to install dependencies
    pause
    exit /b 1
)
echo ✓ Dependencies installed
echo.

echo Step 3: Training the ML model...
cd Backend
python train_model.py
if errorlevel 1 (
    echo Error: Model training failed
    echo Make sure phishing_features.csv exists in the Backend folder
    pause
    exit /b 1
)
echo ✓ Model trained successfully
echo.

echo ========================================
echo Starting Flask API Server...
echo ========================================
echo.
echo The server will run on: http://localhost:5000
echo.
echo To test:
echo 1. Open your browser
echo 2. Navigate to Frontend/public/index.html
echo 3. Click "Phishing Detection"
echo 4. Enter a URL and click "Check"
echo.
echo Press Ctrl+C to stop the server
echo.

python app.py

pause
