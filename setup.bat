@echo off

echo Installing modules from requirements.txt...
echo.

pip install -r requirements.txt

if %errorlevel% equ 0 (
    echo.
    echo Installation completed successfully.
) else (
    echo.
    echo An error occurred during installation.
)

echo.
pause
