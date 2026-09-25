@echo off
SETLOCAL ENABLEDELAYEDEXPANSION

REM ============================================================
REM  Assault Fire Emulator - Launcher (Portable)
REM  - Auto-downloads and installs Python 3.12 if missing
REM  - Auto-detects install directory from batch file location
REM  - Auto-discovers game dir or prompts the user
REM  - Saves game dir to launch.cfg for future runs
REM  - Creates .venv and installs dependencies if missing
REM  - Window 1: Main emulator server (v143b)
REM  - Window 2: TGame datetime patcher
REM ============================================================

REM -- Python version to auto-download if not found --
SET "PY_VERSION=3.12.7"
SET "PY_INSTALLER_URL=https://www.python.org/ftp/python/%PY_VERSION%/python-%PY_VERSION%-amd64.exe"
SET "PY_INSTALLER=%TEMP%\python-%PY_VERSION%-amd64.exe"

REM -- Derive ROOT from the location of this batch file (portable) --
SET "ROOT=%~dp0"
IF "%ROOT:~-1%"=="\" SET "ROOT=%ROOT:~0,-1%"

SET "VENV=%ROOT%\.venv"
SET "PYTHON_EXE=%VENV%\Scripts\python.exe"
SET "REQ=%ROOT%\requirements.txt"
SET "CFG=%ROOT%\launch.cfg"
SET "AF_PRIVATE_KEY_PATH=%ROOT%\server\PRIVATE.PEM"

echo.
echo ============================================================
echo   Assault Fire Emulator - Launcher
echo   ROOT: %ROOT%
echo ============================================================
echo.

REM ------------------------------------------------------------
REM  STEP 1: Detect or auto-install Python 3
REM ------------------------------------------------------------
echo [1/5] Checking for Python 3...

SET "SYS_PYTHON="
python --version >nul 2>&1
IF NOT ERRORLEVEL 1 (
    FOR /F "tokens=2 delims= " %%V IN ('python --version 2^>^&1') DO SET PY_VER=%%V
    FOR /F "tokens=1 delims=." %%M IN ("!PY_VER!") DO SET PY_MAJOR=%%M
    IF !PY_MAJOR! GEQ 3 (
        SET "SYS_PYTHON=python"
        echo  [OK] Python !PY_VER! already installed.
        GOTO python_ok
    ) ELSE (
        echo  [WARN] Python !PY_VER! found but version 3+ is required.
    )
)

REM Check common user-install locations in case PATH is not updated
FOR %%D IN (C D E F) DO (
    FOR %%V IN (313 312 311 310) DO (
        IF EXIST "%%D:\Users\%USERNAME%\AppData\Local\Programs\Python\Python%%V\python.exe" (
            SET "SYS_PYTHON=%%D:\Users\%USERNAME%\AppData\Local\Programs\Python\Python%%V\python.exe"
            echo  [OK] Found Python at: !SYS_PYTHON!
            GOTO python_ok
        )
        IF EXIST "%%D:\Python%%V\python.exe" (
            SET "SYS_PYTHON=%%D:\Python%%V\python.exe"
            echo  [OK] Found Python at: !SYS_PYTHON!
            GOTO python_ok
        )
    )
)

REM Python not found - auto-download and install
echo  [INFO] Python not found. Downloading Python %PY_VERSION%...
echo         This may take a few minutes depending on your connection.
echo.

REM Check if PowerShell is available for download
powershell -Command "exit 0" >nul 2>&1
IF ERRORLEVEL 1 (
    echo  [ERROR] PowerShell is not available. Cannot auto-download Python.
    echo  Please manually install Python 3.11+ from: https://www.python.org/downloads/
    pause
    exit /b 1
)

REM Download installer via PowerShell
echo  [INFO] Downloading from: %PY_INSTALLER_URL%
powershell -NoProfile -Command ^
    "try { Invoke-WebRequest -Uri '%PY_INSTALLER_URL%' -OutFile '%PY_INSTALLER%' -UseBasicParsing; exit 0 } catch { Write-Host '[ERROR]' $_.Exception.Message; exit 1 }"
IF ERRORLEVEL 1 (
    echo.
    echo  [ERROR] Download failed. Check your internet connection and try again.
    echo  You can also install Python manually from: https://www.python.org/downloads/
    pause
    exit /b 1
)
echo  [OK] Download complete.

REM Install Python silently for current user (no admin required)
echo  [INFO] Installing Python %PY_VERSION% (this may take a moment)...
"%PY_INSTALLER%" /quiet InstallAllUsers=0 PrependPath=1 Include_pip=1 Include_launcher=0
IF ERRORLEVEL 1 (
    echo  [ERROR] Python installation failed.
    echo  Please install manually from: https://www.python.org/downloads/
    pause
    exit /b 1
)
echo  [OK] Python %PY_VERSION% installed successfully.
DEL /Q "%PY_INSTALLER%" 2>nul

REM Find newly installed Python
FOR %%D IN (C D E F) DO (
    FOR %%V IN (313 312 311 310) DO (
        IF EXIST "%%D:\Users\%USERNAME%\AppData\Local\Programs\Python\Python%%V\python.exe" (
            SET "SYS_PYTHON=%%D:\Users\%USERNAME%\AppData\Local\Programs\Python\Python%%V\python.exe"
            echo  [OK] Located installed Python: !SYS_PYTHON!
            GOTO python_ok
        )
    )
)

echo  [ERROR] Python was installed but could not be located. Please restart this launcher.
pause
exit /b 1

:python_ok

REM ------------------------------------------------------------
REM  STEP 2: Resolve AF_GAME_DIR
REM    Priority: saved launch.cfg > environment variable > auto-detect > prompt
REM ------------------------------------------------------------
echo.
echo [2/5] Resolving Assault Fire game directory...

SET "AF_GAME_DIR="

REM Check saved config first
IF EXIST "%CFG%" (
    FOR /F "usebackq tokens=1,* delims==" %%K IN ("%CFG%") DO (
        IF "%%K"=="AF_GAME_DIR" SET "AF_GAME_DIR=%%L"
    )
    IF EXIST "!AF_GAME_DIR!\TGame_AFDEV.exe" (
        echo  [OK] Using saved path from launch.cfg:
        echo       !AF_GAME_DIR!
        GOTO game_dir_resolved
    ) ELSE (
        echo  [WARN] Saved path in launch.cfg is no longer valid. Re-detecting...
        SET "AF_GAME_DIR="
    )
)

REM Check environment variable
IF DEFINED AF_GAME_DIR (
    IF EXIST "!AF_GAME_DIR!\TGame_AFDEV.exe" (
        echo  [OK] Using AF_GAME_DIR environment variable:
        echo       !AF_GAME_DIR!
        GOTO game_dir_resolved
    )
    SET "AF_GAME_DIR="
)

REM Auto-detect: check current user Desktop and common install locations
SET "DESKTOP_GUESS=%USERPROFILE%\Desktop\af\Assault Fire 1.0.0.24\Binaries\Win32"
IF EXIST "%DESKTOP_GUESS%\TGame_AFDEV.exe" (
    SET "AF_GAME_DIR=%DESKTOP_GUESS%"
    echo  [OK] Auto-detected on Desktop:
    echo       !AF_GAME_DIR!
    GOTO game_dir_resolved
)

FOR %%D IN (C D E F G) DO (
    FOR %%P IN (
        "%%D:\Program Files\Assault Fire PH\Binaries\Win32"
        "%%D:\Program Files (x86)\Assault Fire PH\Binaries\Win32"
        "%%D:\AssaultFirePH\Binaries\Win32"
        "%%D:\Games\Assault Fire PH\Binaries\Win32"
        "%%D:\Games\AssaultFirePH\Binaries\Win32"
    ) DO (
        IF EXIST %%P\TGame_AFDEV.exe (
            SET "AF_GAME_DIR=%%~P"
            echo  [OK] Auto-detected:
            echo       !AF_GAME_DIR!
            GOTO game_dir_resolved
        )
    )
)

REM Not found - prompt the user
echo.
echo  [WARN] Could not auto-detect the Assault Fire game directory.
echo.
echo  Please enter the full path to your "Binaries\Win32" folder.
echo  Example: C:\Games\AssaultFirePH\Binaries\Win32
echo.
SET /P AF_GAME_DIR="  Game Binaries\Win32 path: "

IF NOT EXIST "!AF_GAME_DIR!" (
    echo  [ERROR] Path does not exist: !AF_GAME_DIR!
    pause
    exit /b 1
)
IF NOT EXIST "!AF_GAME_DIR!\TGame_AFDEV.exe" (
    echo  [ERROR] TGame_AFDEV.exe not found in: !AF_GAME_DIR!
    pause
    exit /b 1
)
echo  [OK] Game directory confirmed.

:game_dir_resolved
REM Save to config for future runs
echo AF_GAME_DIR=!AF_GAME_DIR!> "%CFG%"
echo  [INFO] Path saved to launch.cfg for future runs.

REM ------------------------------------------------------------
REM  STEP 3: Create virtual environment if missing
REM ------------------------------------------------------------
echo.
echo [3/5] Checking virtual environment...
IF NOT EXIST "%VENV%\Scripts\python.exe" (
    echo  [INFO] Virtual environment not found. Creating .venv...
    "!SYS_PYTHON!" -m venv "%VENV%"
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
REM  STEP 4: Install / upgrade dependencies
REM ------------------------------------------------------------
echo.
echo [4/5] Installing dependencies from requirements.txt...
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
REM  STEP 5: Launch both PowerShell windows
REM ------------------------------------------------------------
echo.
echo [5/5] Launching Assault Fire Emulator windows...

echo  >> Starting Main Server...
start "AF Emulator Server" powershell.exe -NoExit -Command ^
    "$env:AF_GAME_DIR = '!AF_GAME_DIR!'; $env:AF_PRIVATE_KEY_PATH = '%AF_PRIVATE_KEY_PATH%'; cd '%ROOT%'; .\.venv\Scripts\python.exe .\server\assaultfire_server_v143b.py"

echo  >> Starting TGame Datetime Patcher...
start "AF TGame Datetime Patch" powershell.exe -NoExit -Command ^
    "cd '%ROOT%'; .\.venv\Scripts\python.exe .\tools\patches\patch_tgame_datetime.py"

echo.
echo  [DONE] Both windows launched successfully.
echo  You can close this window.
echo.
pause
ENDLOCAL
