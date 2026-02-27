@echo off
TITLE SENTINEL FORENSIC SUITE - ANALYST LOADER
SETLOCAL EnableDelayedExpansion

:: --- Visual Header ---
echo.
echo  __________________________________________________________
echo ^|                                                          ^|
echo ^|   SSSSS  EEEEEE  NN   N  TTTTTT  II  N   N  EEEEEE  L      ^|
echo ^|   S      E       N N  N    TT    II  NN  N  E       L      ^|
echo ^|   SSSSS  EEEE    N  N N    TT    II  N N N  EEEE    L      ^|
echo ^|       S  E       N   NN    TT    II  N  NN  E       L      ^|
echo ^|   SSSSS  EEEEEE  N    N    TT    II  N   N  EEEEEE  LLLLLL ^|
echo ^|__________________________________________________________^|
echo           [ CORE LOADER VERSION 2.0 - LIVE FEED ]
echo.

cd /d "%~dp0"

:: --- Admin Privilege Check ---
echo [*] VERIFYING KERNEL PRIVILEGES...
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] ELEVATED ACCESS GRANTED.
) else (
    echo [!] CRITICAL ERROR: INSUFFICIENT PERMISSIONS.
    echo [!] THIS SUITE REQUIRES ACCESS TO SYSTEM HANDLES.
    echo [!] ACTION: RIGHT-CLICK AND 'RUN AS ADMINISTRATOR'.
    echo.
    pause
    exit /b
)

:: --- Python Environment Check ---
echo [*] PROBING PYTHON INTERPRETER...
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [!] ERROR: INTERPRETER NOT FOUND.
    echo [!] PLEASE INSTALL PYTHON 3.X AND ADD TO SYSTEM PATH.
    pause
    exit /b
)

:: --- Launching the Suite ---
echo [*] SYSTEM HIVE: %cd%
echo [*] LOADING SENTINEL CORE...
timeout /t 2 >nul
cls

python main.py

echo.
echo [!] SENTINEL SESSION TERMINATED.
echo [*] ALL VOLATILE DATA CLEARED FROM MEMORY.
pause