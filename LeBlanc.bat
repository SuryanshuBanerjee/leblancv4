@echo off
rem Opens the LeBlanc UI in your browser. Press "Start run" there. Keep this window open while you use the UI;
rem the run itself is a separate process and keeps going if you close it.
cd /d "%~dp0"
set PYTHONIOENCODING=utf-8
start "" http://127.0.0.1:8765
python -m leblanc web
