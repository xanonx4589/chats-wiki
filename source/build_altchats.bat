@echo off
setlocal
cd /d "%~dp0"
set "CRYPTO=crypto\noise.c crypto\sha256.c crypto\chacha20_poly1305.c"
gcc -std=c99 -Os -s -Wall -Wextra -Wpedantic altchats_relay.c %CRYPTO% -static -lws2_32 -ladvapi32 -o altchats_relay.exe
if errorlevel 1 exit /b 1
gcc -std=c99 -Os -s -Wall -Wextra -Wpedantic altchats_client.c altchats_session.c %CRYPTO% -static -lws2_32 -ladvapi32 -o altchats_client.exe
if errorlevel 1 exit /b 1
gcc -std=c99 -Os -s -Wall -Wextra -Wpedantic altchats_web.c altchats_session.c %CRYPTO% -static -lws2_32 -ladvapi32 -o altchats_web.exe
if errorlevel 1 exit /b 1
echo Built all three ALTCHATS executables. Keep altchats.html beside altchats_web.exe.
