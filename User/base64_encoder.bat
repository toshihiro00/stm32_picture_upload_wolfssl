@echo off
chcp 65001 > nul


set outfile="picture_encode_data.h"

rem avoid not argument
if "%~1"=="" (
  echo Not found argment
  pause
  exit /b
)

if exist %1 (

 certutil -f -encode %1 %~n1.h >nul

) else (

 echo not found file

)
