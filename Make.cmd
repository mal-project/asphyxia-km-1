@ECHO OFF
REM Make for MASM32
REM version 5.0.5

REM With this BATCH you can compile, link and lauch
REM .asm files with MASM32 from any folder or partition.

REM -----------------------------------
REM User projets directories...
SET PROJECT=%CD%
SET FILENAME=keygen
SET RES=%PROJECT%\res
SET RESFILE=%RES%\rsrc.rc
SET BIN=%PROJECT%\bin
REM -----------------------------------

REM -----------------------------------
REM Masm32 directories...
REM SET MASMPATH=%systemdrive%/Programs\Development\RCE\Assemblers\MASM
SET MASMPATH=\Portable\Apps\Development\RCE\Assemblers\MASM
REM -----------------------------------

REM -----------------------------------
REM Checking for masm32 directories
IF NOT EXIST %MASMPATH%. (
	FOR %%i IN (C X Y Z) DO (
		IF EXIST %%i:%MASMPATH%. SET MASMPATH=%%i:%MASMPATH%
	)
)
IF NOT EXIST %MASMPATH%. (
    ECHO NO MASM DIRECTORY FOUND! CHECK PATH IN MAKE.CMD
    ECHO MASMPATH=%MASMPATH%
    GOTO ERROR
)
REM -----------------------------------

REM -----------------------------------
SET MASMBIN=%MASMPATH%\bin
REM You may experiment problems with compiled libraries, leave it blank if so...
SET MASMLIB=%MASMPATH%\lib
REM SET MASMLIB=
SET MASMINC=%MASMPATH%\include
SET MASMMACROS=%MASMPATH%\macros
REM -----------------------------------

REM -----------------------------------
REM upx directories...
REM SET UPX=%systemdrive%\Programs\Development\Tools\UPX\upx.exe
SET UPXPATH=\Portable\Apps\Development\RCE\Tools\Packers
REM -----------------------------------

REM -----------------------------------
REM Checking for upx directories
IF NOT EXIST %UPXPATH%. (
	FOR %%j IN (C X Y Z) DO (
		IF EXIST %%j:%UPXPATH%. SET UPXPATH=%%j:%UPXPATH%
	)
)
IF NOT EXIST %UPXPATH%. (
    ECHO NO UPX DIRECTORY FOUND! CHECK PATH IN MAKE.CMD
)
REM -----------------------------------
REM Logging some useful hints when problems occurs...
ECHO MASMPATH=%MASMPATH% > "%PROJECT%\make.log"
ECHO UPXPATH=%UPXPATH% >> "%PROJECT%\make.log"
ECHO PROJECT=%PROJECT% >> "%PROJECT%\make.log"
REM -----------------------------------
ECHO Make.cmd version 5.0
ECHO Tuesday, November 11, 2008

ECHO.
ECHO Compiling resources...
ECHO .......................................

"%MASMBIN%\rc.exe" /i %MASMINC% /i %MASMMACROS% /l0 "%RESFILE%" >> "%PROJECT%\make.log"
"%MASMBIN%\cvtres.exe" /nologo /machine:ix86 "%RES%\rsrc.res" >> "%PROJECT%\make.log"
IF %ERRORLEVEL% NEQ 0 (
    GOTO ERROR
) ELSE (
	DEL "%\%RES%\*.obj"
)

ECHO.
ECHO Building...
ECHO .......................................

"%MASMBIN%\ml.exe" /I"%MASMINC%" /I"%MASMMACROS%" /c /coff /nologo  "%PROJECT%\%FILENAME%.asm" >> "%PROJECT%\make.log"
IF %ERRORLEVEL% NEQ 0 GOTO    ERROR

ECHO.
ECHO Linking...
ECHO .......................................
REM cheking if %masmlib% was blank
IF EXIST "%MASMLIB%\kernel32.lib". (
	"%MASMBIN%\link.exe" /LIBPATH:"%MASMLIB%" /nologo /SUBSYSTEM:WINDOWS /SECTION:.text,REW /OUT:"%BIN%\%FILENAME%.exe" "%PROJECT%\%FILENAME%.obj" "%RES%\rsrc.res" >> "%PROJECT%\make.log"
) ELSE (
	"%MASMBIN%\link.exe" /nologo /SUBSYSTEM:WINDOWS /SECTION:.text,REW /OUT:"%BIN%\%FILENAME%.exe" "%PROJECT%\%FILENAME%.obj" "%RES%\rsrc.res" >> "%PROJECT%\make.log"
)
IF %ERRORLEVEL% NEQ 0 GOTO    ERROR

IF EXIST "%PROJECT%\*.obj" DEL "%PROJECT%\*.obj"
IF EXIST "%RES%\*.res" DEL "%RES%\*.res"

REM -----------------------------------
:OK
ECHO.
ECHO Ok. Everything seems fine. What you wanna do now?
SET /P CHOISE=Compress/Launch/Exit? (c/l/cl/e)

IF %CHOISE%==c (
	ECHO.
	ECHO Compressing...
	START /D"%UPXPATH%" upx.exe -9 "%BIN%\%FILENAME%.exe"
	GOTO FINISH
)

IF %CHOISE%==l (
	ECHO.
	ECHO Executing...
	REM be aware that if %FILENAME% have spaces there is a problem...
	START /D"%BIN%" %FILENAME%.exe
	GOTO FINISH
)

IF %CHOISE%==cl (
    ECHO.
	ECHO Compressing and launching...
	START /WAIT /D"%UPXPATH%" upx.exe -9 "%BIN%\%FILENAME%.exe"
	START /D"%BIN%" %FILENAME%.exe
)
GOTO FINISH
REM -----------------------------------

REM -----------------------------------
:ERROR
ECHO.
ECHO AN ERROR HAS OCCURRED! CHECK LOG FOR DETAILS.
ECHO.
SET /P CHOISE=Open log in notepad? (y/n)
IF %CHOISE%==y START notepad.exe "%PROJECT%\make.log"
EXIT

:FINISH
DEL "%PROJECT%\make.log"
EXIT
