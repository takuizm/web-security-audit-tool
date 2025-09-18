@echo off
title Web Security Audit Tool - Running...

echo ==========================================
echo   Web Security Audit Tool - Execute
echo ==========================================
echo.

REM Check virtual environment
if not exist "venv\Scripts\activate.bat" (
    echo [ERROR] Setup not completed
    echo.
    echo Please run setup.bat first
    pause
    exit /b 1
)

REM Activate virtual environment
echo Preparing environment...
call venv\Scripts\activate.bat

REM Load environment variables
if exist ".env" (
    for /f "tokens=1,2 delims==" %%a in (.env) do (
        set "%%a=%%b"
    )
)

REM Check input file
if not exist targets.csv (
    echo [ERROR] targets.csv file not found
    echo.
    echo Please create targets.csv file with the following format:
    echo url,site_name,priority,notes
    echo https://example.com,Sample Site,high,Important site
    echo https://test.com,Test Site,medium,Development environment
    echo.
    pause
    exit /b 1
)

echo Checking targets.csv content...
echo.
echo --- Target URLs ---
type targets.csv
echo.
echo ------------------
echo.

set /p confirm="Start audit with these URLs? (y/N): "
if /i not "%confirm%"=="y" (
    echo Audit canceled.
    echo Please edit targets.csv and run again.
    pause
    exit /b 0
)

echo.
echo Starting security audit...
echo Results will be saved to output folder.
echo.

REM Create output directory
if not exist output mkdir output

REM Generate timestamp for output folder
for /f "tokens=2-4 delims=/ " %%a in ('date /t') do set DATE=%%c%%a%%b
for /f "tokens=1-2 delims=: " %%a in ('time /t') do set TIME=%%a%%b
set TIMESTAMP=%DATE%_%TIME%

REM Set Python path
set PYTHONPATH=%PYTHONPATH%;%CD%\src

REM Execute audit
echo Running audit...
python -m src.main targets.csv -o output\result_%TIMESTAMP%

if %errorlevel% equ 0 (
    echo.
    echo ==========================================
    echo Audit Complete!
    echo ==========================================
    echo.
    echo Generated files:
    dir /b output\result_%TIMESTAMP%\*.* 2>nul
    echo.
    echo Check output\result_%TIMESTAMP% folder for detailed results.
    echo.
    echo Key files:
    echo - security_audit_report.html (Open with browser)
    echo - security_compliance_evaluation.csv (Open with Excel)
) else (
    echo.
    echo [ERROR] Audit failed
    echo.
    echo Troubleshooting:
    echo 1. Check internet connection
    echo 2. Verify URLs in targets.csv
    echo 3. Check logs\audit.log for details
)

echo.
pause
