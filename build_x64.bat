@echo off
chcp 65001 >nul
echo ========================================================
echo Сборка DataMasker для 64-битных систем (x64)
echo ========================================================

REM Поиск python x64
set "PY_CMD=python"
if exist "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" (
    set "PY_CMD=%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
)

echo Используется интерпретатор: %PY_CMD%
%PY_CMD% -m pip install -r requirements.txt

echo.
echo Запуск PyInstaller...
%PY_CMD% -m PyInstaller --noconsole --onefile --name "DataMasker_x64" ^
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
echo Сборка x64 завершена! Исполняемый файл: dist\DataMasker_x64.exe
echo ========================================================
pause
