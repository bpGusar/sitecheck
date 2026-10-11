@echo off
chcp 65001 >nul
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" goto venv_ready
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 -m venv .venv
) else (
  python -m venv .venv
)
if not exist ".venv\Scripts\python.exe" (
  echo Не найден Python. Установите Python 3.10 или новее: https://www.python.org/downloads/
  echo При установке отметьте галочку "Add python.exe to PATH".
  pause
  exit /b 1
)

:venv_ready
".venv\Scripts\python.exe" -c "import sys; sys.exit(sys.version_info < (3, 10))"
if errorlevel 1 (
  echo Нужен Python 3.10 или новее. Установите его с https://www.python.org/downloads/,
  echo удалите папку .venv и запустите снова.
  pause
  exit /b 1
)

fc /b requirements.txt ".venv\requirements.txt" >nul 2>nul
if errorlevel 1 (
  echo Первый запуск или обновление: ставлю зависимости и Chromium, это несколько минут...
  ".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt || goto failed
  ".venv\Scripts\python.exe" -m playwright install chromium || goto failed
  copy /y requirements.txt ".venv\requirements.txt" >nul
)

".venv\Scripts\python.exe" -m app.main
pause
exit /b 0

:failed
echo Установка не удалась, текст ошибки выше.
pause
exit /b 1
