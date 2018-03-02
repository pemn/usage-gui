@goto :CMD
'''
:CMD
:: calls python bundled with Vulcan on a file of the same name as this script
@echo off
setlocal
if defined VULCAN_EXE goto :VULCAN_OK

set typelib=HKLM\SOFTWARE\Classes\TypeLib\{322858FC-9F41-416D-85DC-610C70A51111}\3.0\HELPDIR

for /f "tokens=2 delims=:" %%i in ('reg.exe query %typelib%') do set VULCAN_EXE=%%~si

:: setup vulcan enviroment
set VULCAN_BIN=%VULCAN_EXE:~0,-4%
set VULCAN=%VULCAN_EXE:~0,-8%
set PATH=%VULCAN_EXE%;%VULCAN_BIN%;%VULCAN_BIN%cygnus\bin;%VULCAN_BIN%other\x86;%PATH%
set PERLLIB=%VULCAN%lib\perl;%VULCAN%lib\perl\site\lib
set VULCAN_VERSION_MAJOR=10

:VULCAN_OK

"%VULCAN_EXE%python.exe" -x %0
goto :EOF
:: '''
from _gui import *

usage_gui(None)
