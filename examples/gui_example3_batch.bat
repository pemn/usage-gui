@echo off

if "%1" equ "" (
    echo "usage: %0 input*csv selection=a,b,c numeric_option=123 boolean_option@ grid_option#csv_column:input output*csv"
    goto :EOF
)

echo argv: %*


