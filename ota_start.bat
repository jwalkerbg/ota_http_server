rem http_server starter for runing behind Apache SSL reverse proxy virtual host.

@echo off
rem Edit next line according your actual environment.
set PYTHONHOME=c:\Python\Python313

@call .venv\Scripts\activate.bat

rem Staring server with no certificates and with token authentication.
rem Run python http_server.py to see all options.
python http_server.py --port 8071 --no-certs
