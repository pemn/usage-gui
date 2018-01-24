::cmd.exe
:: calls python bundled with Vulcan on a file of the same name as this script
@echo off
setlocal
set typelib=HKLM\SOFTWARE\Classes\TypeLib\{322858FC-9F41-416D-85DC-610C70A51111}\3.0\HELPDIR
for /f "tokens=2 delims=:" %%i in ('reg.exe query %typelib%') do set VULCAN_EXE=%SYSTEMDRIVE%%%i

:: setup vulcan enviroment
set VULCAN_BIN=%VULCAN_EXE:~0,-4%
set VULCAN=%VULCAN_EXE:~0,-8%
set PATH=%VULCAN_EXE%;%VULCAN_BIN%oda;%VULCAN_BIN%cygnus\bin;%PATH%
set PERLLIB=%VULCAN%lib\perl;%VULCAN%lib\perl\site\lib;

"%VULCAN_EXE%python.exe" %~dpn0.py
