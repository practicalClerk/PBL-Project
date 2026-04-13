@echo off
echo.
echo ========================================
echo Flask Application - Quick Start
echo ========================================
echo.

cd /d "%~dp0"

echo Step 1: Checking if model files exist...
if exist "phishing_model.pkl" (
    echo ✓ phishing_model.pkl found
) else (
    echo ✗ phishing_model.pkl not found
    echo   Running train_model.py...
    python train_model.py
    if errorlevel 1 (
        echo Error: Failed to train model
        pause
        exit /b 1
    )
)

if exist "scaler.pkl" (
    echo ✓ scaler.pkl found
) else (
    echo ✗ scaler.pkl not found
    echo   Please run: python train_model.py
    pause
    exit /b 1
)

echo.
echo Step 2: Checking project structure...
if exist "templates\index.html" (echo ✓ templates\index.html) else (echo ✗ templates\index.html MISSING)
if exist "templates\PHISHING.HTML" (echo ✓ templates\PHISHING.HTML) else (echo ✗ templates\PHISHING.HTML MISSING)
if exist "static\css\style.css" (echo ✓ static\css\style.css) else (echo ✗ static\css\style.css MISSING)
if exist "app.py" (echo ✓ app.py) else (echo ✗ app.py MISSING)

echo.
echo ========================================
echo Starting Flask Server...
echo ========================================
echo.
echo Server will run on: http://localhost:5000
echo.
echo Available routes:
echo   - Homepage:          http://localhost:5000/
echo   - Phishing Detection: http://localhost:5000/phishing
echo   - About:             http://localhost:5000/knowmore
echo   - Contact:           http://localhost:5000/contact
echo   - API Health:        http://localhost:5000/api/health
echo.
echo Press Ctrl+C to stop the server
echo.

if exist ".venv\Scripts\activate.bat" (
    echo Activating virtual environment...
    call .venv\Scripts\activate.bat
    python app.py
) else (
    echo Warning: Virtual environment not found, using system Python
    python app.py
)

pause
