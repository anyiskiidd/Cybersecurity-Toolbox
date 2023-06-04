@echo off

echo Installing modules from requirements.txt...
echo.

pip install -r requirements.txt

if %errorlevel% equ 0 (
    echo.
    echo Installation completed successfully.
    echo.
    echo Running main.py...
    echo.

    python main.py
) else (
    echo.
    echo An error occurred during installation. The program will not be run.
)

echo.
pause
