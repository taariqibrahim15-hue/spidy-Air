@echo off
REM wifi-auditor native build (MinGW-w64) - no make required.
REM Run from the native\ folder:  build.bat

setlocal
set SRC=src
set BUILD=build
if not exist "%BUILD%" mkdir "%BUILD%"

echo [1/4] Compiling C core (wifi_scan.c)...
gcc -O2 -Wall -municode -c "%SRC%\wifi_scan.c" -o "%BUILD%\wifi_scan.o" || goto :err

echo [2/4] Compiling C++ GUI (main.cpp)...
g++ -O2 -Wall -std=c++17 -municode -I"%SRC%" -c "%SRC%\main.cpp" -o "%BUILD%\main.o" || goto :err

echo [3/4] Compiling resources (icon + manifest)...
windres -I"%SRC%" "%SRC%\app.rc" -O coff -o "%BUILD%\app_res.o" || goto :err

echo [4/4] Linking wifi-auditor.exe...
g++ "%BUILD%\wifi_scan.o" "%BUILD%\main.o" "%BUILD%\app_res.o" -o "%BUILD%\wifi-auditor.exe" ^
    -municode -mwindows -static -static-libgcc -static-libstdc++ -lwlanapi -lcomctl32 -lole32 || goto :err

echo.
echo Done -> %BUILD%\wifi-auditor.exe
goto :eof

:err
echo.
echo BUILD FAILED. Make sure MinGW-w64 (gcc/g++/windres) is on PATH.
exit /b 1
