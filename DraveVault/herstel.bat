@echo off
REM ============================================================
REM  DraveVault - herstel (wist en herbouwt de .venv)
REM ============================================================
setlocal
cd /d "%~dp0"
echo Dit verwijdert de map .venv en installeert alles opnieuw.
echo (Je kluis in DraveVault-data blijft staan.)
pause
if exist ".venv" rmdir /s /q ".venv"

set "PYEXE="
for %%V in (3.13 3.12 3.11 3.10) do (
    if not defined PYEXE (
        py -%%V -c "import sys" >nul 2>&1 && set "PYEXE=py -%%V"
    )
)
if not defined PYEXE python -c "import sys" >nul 2>&1 && set "PYEXE=python"
if not defined PYEXE (
    echo Geen geschikte Python gevonden.
    pause
    exit /b 1
)
%PYEXE% -m venv .venv
call ".venv\Scripts\activate.bat"
python -m pip install --upgrade pip --quiet
python -m pip install --only-binary=:all: -r requirements.txt
echo Klaar.
pause
