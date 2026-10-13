@echo off
chcp 65001 >nul
echo ========================================================
echo Сборка DataMasker для 32-битных систем (x86)
echo ========================================================

REM Поиск python 32-bit
set "PY_CMD=python"
if exist "%LOCALAPPDATA%\Programs\Python\Python311-32\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python311-32\python.exe"
)

echo Используется интерпретатор: %PY_CMD%

echo.
echo Запуск PyInstaller (x86)...
%PY_CMD% -m PyInstaller --noconsole --onefile --name "DataMasker_x86" ^
    --collect-all customtkinter ^
    --collect-all natasha ^
    --collect-all navec ^
    --collect-all slovnet ^
    --collect-all yargy ^
    --collect-all razdel ^
    --collect-all docx ^
    --collect-all openpyxl ^
    --collect-all pypdf ^
    --collect-all pptx ^
    --collect-all xlrd ^
    --collect-all xlwt ^
    --collect-all xlutils ^
    --collect-all olefile ^
    --collect-all striprtf ^
    main.py

echo.
echo ========================================================
echo Сборка x86 завершена! Исполняемый файл: dist\DataMasker_x86.exe
echo ========================================================
pause
