@echo off

rem
rem Script to invoke the ConfigTool class
rem 
rem Author: Gregor Karlinger
rem Version: $Id:  $
rem


if %OS%=="Windows_NT" @setlocal

set CONFIGTOOL=at.gv.egovernment.moa.spss.server.tools.ConfigTool
set TOOLSPATH=%~p0
set CLASSPATH=%TOOLSPATH%tools.jar;%TOOLSPATH%xalan.jar;

if "%JAVA_HOME%"=="" goto noJavaHome
%JAVA_HOME%\bin\java.exe -classpath %CLASSPATH% %CONFIGTOOL% %1 %2 %3 %4 %5 %6 %7 %8 %9
goto end

:noJavaHome
echo error: JAVA_HOME not defined

:end
if %OS%=="Windows_NT" @endlocal