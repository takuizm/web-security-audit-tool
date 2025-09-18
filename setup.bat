@echo off
echo ==========================================
echo   Web Security Audit Tool - Setup (Windows)
echo ==========================================
echo.

REM Python check
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python not found
    echo.
    echo Please install Python 3.9 or later:
    echo https://www.python.org/downloads/
    echo.
    echo IMPORTANT: Check "Add Python to PATH" during installation
    pause
    exit /b 1
)

echo [OK] Python found
python --version

REM Create virtual environment
echo.
echo Creating virtual environment...
python -m venv venv
if %errorlevel% neq 0 (
    echo [ERROR] Failed to create virtual environment
    pause
    exit /b 1
)

REM Activate virtual environment
echo.
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Upgrade pip
echo.
echo Upgrading pip...
python -m pip install --upgrade pip

REM Install dependencies - split into multiple lines to avoid long command issues
echo.
echo Installing required libraries...
pip install requests>=2.31.0
pip install beautifulsoup4>=4.12.0
pip install selenium>=4.15.0
pip install pandas>=2.1.0
pip install pyyaml>=6.0.1
pip install jinja2>=3.1.2
pip install structlog>=23.1.0
pip install cryptography>=41.0.0

if %errorlevel% neq 0 (
    echo [ERROR] Failed to install dependencies
    echo.
    echo Please check your internet connection
    pause
    exit /b 1
)

REM ChromeDriver check and download
echo.
echo Checking ChromeDriver...
where chromedriver >nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] ChromeDriver found
) else (
    if exist chromedriver.exe (
        echo [OK] ChromeDriver found in current directory
    ) else (
        echo [INFO] Downloading ChromeDriver...
        python -c "import requests, zipfile, os; r=requests.get('https://chromedriver.storage.googleapis.com/LATEST_RELEASE'); v=r.text.strip(); r2=requests.get(f'https://chromedriver.storage.googleapis.com/{v}/chromedriver_win32.zip'); open('cd.zip','wb').write(r2.content); zipfile.ZipFile('cd.zip').extractall('.'); os.remove('cd.zip'); print('[OK] ChromeDriver downloaded')" 2>nul
        if %errorlevel% neq 0 (
            echo [WARN] ChromeDriver download failed
            echo Please download manually from: https://chromedriver.chromium.org/
        )
    )
)

REM Setup configuration files
echo.
echo Setting up configuration files...
if exist .env (
    echo [OK] Environment file (.env) exists
) else (
    if exist env.example (
        copy env.example .env >nul
        echo [OK] Created environment file (.env)
        echo [INFO] Edit .env file to configure API keys if needed
    ) else (
        echo [WARN] Environment template file not found
    )
)

echo.
echo ==========================================
echo Setup Complete!
echo ==========================================
echo.
echo Next steps:
echo 1. Edit targets.csv with URLs to audit
echo 2. Run run.bat to start security audit
echo.
echo For detailed instructions, see:
echo - README.md
echo.
pause
