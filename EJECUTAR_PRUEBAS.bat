@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Cuidarte+ QA - Ejecucion de pruebas
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0QA\scripts\ejecutar-evidencias.ps1"
echo.
echo Ejecucion terminada. Puede cerrar esta ventana.
pause
