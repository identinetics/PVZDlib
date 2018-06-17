@echo off

rem
rem Script to invoke the CertTool class
rem 
rem Author: Patrick Peck
rem Version: $Id: certtool.bat,v 1.6 2003/05/08 11:46:29 peck Exp $
rem


if %OS%=="Windows_NT" @setlocal

set CERTTOOL=at.gv.egovernment.moa.spss.server.tools.CertTool
set TOOLSPATH=%~p0
set CLASSPATH=%TOOLSPATH%tools.jar;%TOOLSPATH%iaik_moa.jar;%TOOLSPATH%iaik_jce_full.jar;%TOOLSPATH%iaik_ecc.jar;%TOOLSPATH%log4j.jar

if "%JAVA_HOME%"=="" goto noJavaHome
%JAVA_HOME%\bin\java.exe -classpath %CLASSPATH% %CERTTOOL% %1 %2 %3 %4 %5 %6 %7 %8 %9
goto end

:noJavaHome
echo error: JAVA_HOME not defined

:end
if %OS%=="Windows_NT" @endlocal