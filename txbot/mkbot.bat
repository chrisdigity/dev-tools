@echo off
rem Change the next line for your compiler:
set CC=bcc32 -DWIN32 %1 %2 %3 %4 %5 %6 %7 %8
if not exist txbot.c goto usage
echo Building txbot...
%CC% -c sha256.c      >ccerror.log
%CC% -c wots/wots.c   >>ccerror.log
%CC% txbot.c wots.obj sha256.obj >>ccerror.log
rem next line for Borland C++ 5.5
if exist *.tds del *.tds
echo.
echo Compiler messages are in ccerror.log
echo.
dir ccerror.log
echo.
echo Type 'txbot -h' for help.
echo.
goto end
rem To make clean:
rem del sha256.obj wots.obj txbot.obj ccerror.log
:usage
echo From source directory type:
echo        mkbot   to compile
echo        txbot   to run txbot
echo.
:end
