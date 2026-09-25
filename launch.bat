@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

REM ============================================================
REM  Assault Fire Emulator - Launcher
REM  - Checks for Python 3
REM  - Creates .venv if missing
REM  - Installs dependencies from requirements.txt if needed
REM  - Window 1: Main emulator server (v143b)
REM  - Window 2: TGame datetime patcher
REM ============================================================

SET ROOT=C:\Users\Administrator\Desktop\af\af-emulator-main
SET AF_GAME_DIR=C:\Users\Administrator\Desktop\af\Assault Fire 1.0.0.24\Binaries\Win32
SET AF_PRIVATE_KEY_PATH=%ROOT%\server\PRIVATE.PEM
SET VENV=%ROOT%\.venv
SET PYTHON_EXE=%VENV%\Scripts\python.exe
SET REQ=%ROOT%\requirements.txt

echo.
echo ============================================================
echo   Assault Fire Emulator - Launcher
echo ============================================================
echo.

REM ------------------------------------------------------------
REM  STEP 1: Check for Python 3 on the system
REM ------------------------------------------------------------
echo [1/4] Checking for Python 3...
python --version >nul 2>&1
IF ERRORLEVEL 1 (
    echo.
    echo  [ERROR] Python is NOT installed or not in PATH.
    echo.
    echo  Please download and install Python 3.11 or newer from:
    echo    https://www.python.org/downloads/
    echo.
    echo  Make sure to check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)

FOR /F "tokens=2 delims= " %%V IN ('python --version 2^>^&1') DO SET PY_VER=%%V
FOR /F "tokens=1 delims=." %%M IN ("!PY_VER!") DO SET PY_MAJOR=%%M
IF !PY_MAJOR! LSS 3 (
    echo.
    echo  [ERROR] Python 3 is required, but Python !PY_VER! was found.
    echo  Please install Python 3.11+ from https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)
echo  [OK] Python !PY_VER! found.

REM ------------------------------------------------------------
REM  STEP 2: Create virtual environment if it doesn't exist
REM ------------------------------------------------------------
echo.
echo [2/4] Checking virtual environment...
IF NOT EXIST "%VENV%\Scripts\python.exe" (
    echo  [INFO] Virtual environment not found. Creating .venv...
    python -m venv "%VENV%"
    IF ERRORLEVEL 1 (
        echo  [ERROR] Failed to create virtual environment.
        pause
        exit /b 1
    )
    echo  [OK] Virtual environment created.
) ELSE (
    echo  [OK] Virtual environment already exists.
)

REM ------------------------------------------------------------
REM  STEP 3: Install / upgrade dependencies from requirements.txt
REM ------------------------------------------------------------
echo.
echo [3/4] Installing dependencies from requirements.txt...
IF NOT EXIST "%REQ%" (
    echo  [WARN] requirements.txt not found - skipping dependency install.
) ELSE (
    "%PYTHON_EXE%" -m pip install --quiet --upgrade pip
    "%PYTHON_EXE%" -m pip install --quiet -r "%REQ%"
    IF ERRORLEVEL 1 (
        echo  [ERROR] Failed to install dependencies. Check your internet connection.
        pause
        exit /b 1
    )
    echo  [OK] Dependencies installed/up-to-date.
)

REM ------------------------------------------------------------
REM  STEP 4: Launch both PowerShell windows
REM ------------------------------------------------------------
echo.
echo [4/4] Launching Assault Fire Emulator windows...

echo  >> Starting Main Server...
start "AF Emulator Server" powershell.exe -NoExit -Command ^
    "cd '%ROOT%'; $env:AF_GAME_DIR = '%AF_GAME_DIR%'; $env:AF_PRIVATE_KEY_PATH = '%AF_PRIVATE_KEY_PATH%'; .\.venv\Scripts\python.exe .\server\assaultfire_server_v143b.py"

echo  >> Starting TGame Datetime Patcher...
start "AF TGame Datetime Patch" powershell.exe -NoExit -Command ^
    "cd '%ROOT%'; .\.venv\Scripts\python.exe .\tools\patches\patch_tgame_datetime.py"

echo.
echo  [DONE] Both windows launched successfully.
echo  You can close this window.
echo.
pause
ENDLOCAL
