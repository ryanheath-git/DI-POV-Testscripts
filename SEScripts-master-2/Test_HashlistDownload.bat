@echo off

@ECHO OFF
SET index=1
SETLOCAL ENABLEDELAYEDEXPANSION
FOR %%f IN (*manifest.*) DO (
	SET file!index!=%%f
   	ECHO !index! - %%f
   	SET /A index=!index!+1
)

if "%index%" equ "1" (
	ECHO No files to choose from.  Please copy a file in the format of *manifest.* into this folder.
	pause
   	EXIT /B 1
)

SETLOCAL DISABLEDELAYEDEXPANSION
SET /P selection="Select hashfile by number: "
SET file%selection% >nul 2>&1
IF ERRORLEVEL 1 (
   	ECHO Invalid number selected   
   	pause
   	EXIT /B 1
)
CALL :RESOLVE %%file%selection%%%
GOTO :EOF

:RESOLVE
SET file_name=%1
ECHO Downloading hashes in file %file_name%
python malware_downloader.py -a d147ce212710591966d7fdcc00b27cb1ae228bb8571664c22f999102748ca9b0 -r VT3 -o ./MALWARE -n 20 %file_name%

pause
