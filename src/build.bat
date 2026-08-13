@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul 2>&1
title Wisp C2 Framework - Windows Build Script

rem ============================================================
rem  Wisp C2 Framework - Windows Build Script
rem  Usage:  build.bat [command]
rem
rem  Commands:
rem    all          Build frontend + server + agent (default)
rem    frontend     Build frontend only
rem    server       Build frontend + server (wisp.exe)
rem    agent        Build agent for current platform
rem    agent-all    Cross-compile agent for all 6 platforms
rem    templates    Build 6-platform agent templates + 2 DLL templates into bin\templates
rem    release      Stage loaders/native/scripts resources into bin\
rem    clean        Remove build artifacts
rem    help         Show usage
rem ============================================================

set "PROJECT_ROOT=%~dp0"
set "BIN_DIR=%PROJECT_ROOT%bin"
set "FRONTEND_DIR=%PROJECT_ROOT%frontend"
set "AGENT_DIR=%PROJECT_ROOT%agent"
set "SRV_DIR=%PROJECT_ROOT%services"

set "CMD=%~1"
if "%CMD%"=="" set "CMD=all"

echo.
echo  Wisp C2 Framework - Build Script
echo  =================================
echo.

rem ---------- tool checks ----------
echo [Check] Verifying build tools...
set "TOOL_OK=1"

where go >nul 2>&1
if errorlevel 1 (
    echo   [FAIL] Go not found. Install Go 1.25+: https://go.dev/dl/
    set "TOOL_OK=0"
) else (
    for /f "tokens=3 delims= " %%v in ('go version') do echo   [OK]   Go %%v
)

where node >nul 2>&1
if errorlevel 1 (
    echo   [FAIL] Node.js not found. Install Node 20+: https://nodejs.org/
    set "TOOL_OK=0"
) else (
    for /f "tokens=1 delims= " %%v in ('node --version') do echo   [OK]   Node %%v
)

where npm >nul 2>&1
if errorlevel 1 (
    echo   [FAIL] npm not found.
    set "TOOL_OK=0"
) else (
    for /f "tokens=1 delims= " %%v in ('npm --version') do echo   [OK]   npm %%v
)

rem Locate gcc: check PATH first, then auto-discover MinGW-w64 under winget packages.
where gcc >nul 2>&1
if not errorlevel 1 goto :gcc_found

echo   gcc not in PATH, searching winget-installed MinGW-w64...
for /r "%LOCALAPPDATA%\Microsoft\WinGet\Packages" %%f in (gcc.exe) do (
    if exist "%%f" (
        echo   [OK]   Found gcc: %%f
        set "PATH=%%~dpf;%PATH%"
        goto :gcc_found
    )
)

echo   [FAIL] gcc not found. The server needs CGO to build go-sqlite3.
echo           Install MinGW-w64 GCC, e.g.:
echo             winget install -e --id BrechtSanders.WinLibs.POSIX.UCRT
echo             or download from: https://winlibs.com/
echo           Then make sure `gcc` is in PATH (reopen the terminal).
set "TOOL_OK=0"
goto :gcc_done

:gcc_found
for /f "tokens=1,2 delims= " %%a in ('gcc --version 2^>nul ^| findstr /i "gcc"') do echo   [OK]   %%a %%b

:gcc_done
if "!TOOL_OK!"=="0" (
    echo.
    echo [ERROR] Missing required tools. Please install them and re-run.
    exit /b 1
)
echo.

rem ---------- main dispatch (jump over function definitions) ----------
if /i "%CMD%"=="frontend"     goto :do_frontend
if /i "%CMD%"=="server"       goto :do_server
if /i "%CMD%"=="agent"        goto :do_agent
if /i "%CMD%"=="agent-all"    goto :do_agent_all
if /i "%CMD%"=="templates"    goto :do_templates
if /i "%CMD%"=="release"      goto :do_release
if /i "%CMD%"=="clean"        goto :do_clean
if /i "%CMD%"=="help"         goto :usage
if /i "%CMD%"=="all"          goto :do_all
echo   [ERROR] Unknown command: %CMD%
call :usage
exit /b 1

:do_release
rem Stage the operator resource directories into bin\ (loaders, native, scripts).
echo [Step] Staging release resources -^> bin\
if exist "%PROJECT_ROOT%loaders" (
    if exist "%BIN_DIR%\loaders" rmdir /s /q "%BIN_DIR%\loaders"
    xcopy /e /i /q "%PROJECT_ROOT%loaders" "%BIN_DIR%\loaders" >nul
    echo   [OK]   loaders\ copied
)
if exist "%PROJECT_ROOT%native" (
    if exist "%BIN_DIR%\native" rmdir /s /q "%BIN_DIR%\native"
    xcopy /e /i /q "%PROJECT_ROOT%native" "%BIN_DIR%\native" >nul
    echo   [OK]   native\ copied
)
if not exist "%BIN_DIR%\scripts" mkdir "%BIN_DIR%\scripts"
if not exist "%BIN_DIR%\payloads" mkdir "%BIN_DIR%\payloads"
if not exist "%BIN_DIR%\reports" mkdir "%BIN_DIR%\reports"
goto :done

:do_frontend
call :build_frontend
goto :done

:do_server
call :build_frontend
if errorlevel 1 exit /b 1
call :build_server
goto :done

:do_agent
call :build_agent
goto :done

:do_agent_all
call :build_agent_all
goto :done

:do_templates
call :build_templates
goto :done

:do_clean
call :clean
goto :done

:do_all
call :build_frontend
if errorlevel 1 exit /b 1
call :build_templates
if errorlevel 1 exit /b 1
call :build_server
if errorlevel 1 exit /b 1
call :build_agent
goto :done

rem ---------- sub functions ----------

:build_templates
echo [Step] Building agent templates (6 platforms + DLL, no config -^> bin\templates)...
if not exist "%BIN_DIR%\templates" mkdir "%BIN_DIR%\templates"
call :build_template windows amd64
call :build_template windows arm64
call :build_template linux amd64
call :build_template linux arm64
call :build_template darwin amd64
call :build_template darwin arm64
call :build_dll_template windows amd64
call :build_dll_template windows arm64
echo   [OK]   Templates built -^> bin\templates\
exit /b 0

:build_template
set "_OS=%~1"
set "_ARCH=%~2"
set "_NAME=agent_%_OS%_%_ARCH%"
set "_GUI="
if "%_OS%"=="windows" (
    set "_NAME=%_NAME%.exe"
    set "_GUI=-H windowsgui"
)
set "CGO_ENABLED=0"
set "GOOS=%_OS%"
set "GOARCH=%_ARCH%"
pushd "%AGENT_DIR%"
call go build -ldflags="-s -w !_GUI!" -trimpath -o "%BIN_DIR%\templates\%_NAME%" .
if errorlevel 1 (
    echo   [ERROR] Template build failed for %_OS%/%_ARCH%.
    popd
    exit /b 1
)
popd
set "GOOS="
set "GOARCH="
echo   [OK]   Template %_NAME%
exit /b 0
if errorlevel 1 (
    echo   [ERROR] Template build failed for %_OS%/%_ARCH%.
    popd
    exit /b 1
)
popd
echo   [OK]   Template %_NAME%
exit /b 0

:build_dll_template
set "_OS=%~1"
set "_ARCH=%~2"
set "_NAME=agent_%_OS%_%_ARCH%.dll"
echo   Building DLL template %_NAME% (c-shared, needs gcc)...
set "CGO_ENABLED=1"
set "GOOS=%_OS%"
set "GOARCH=%_ARCH%"
pushd "%AGENT_DIR%"
go build -buildmode=c-shared -ldflags="-s -w" -trimpath -o "%BIN_DIR%\templates\%_NAME%" .
if errorlevel 1 goto :dll_fail
popd
set "GOOS="
set "GOARCH="
if exist "%BIN_DIR%\templates\agent_%_OS%_%_ARCH%.h" del "%BIN_DIR%\templates\agent_%_OS%_%_ARCH%.h"
echo   [OK]   DLL template %_NAME%
exit /b 0

:dll_fail
echo   [WARN] DLL template %_NAME% failed to build (gcc for %_OS%/%_ARCH% required; skipping, exe templates are unaffected).
popd
set "GOOS="
set "GOARCH="
exit /b 0

:build_frontend
echo [Step] Building frontend...
if not exist "%FRONTEND_DIR%\node_modules" (
    echo   npm install...
    pushd "%FRONTEND_DIR%"
    call npm install
    if errorlevel 1 (
        echo   [ERROR] npm install failed.
        popd
        exit /b 1
    )
    popd
)
call :ensure_platform_deps
if errorlevel 1 exit /b 1
pushd "%FRONTEND_DIR%"
call npm run build
if errorlevel 1 (
    echo   [ERROR] Frontend build failed.
    popd
    exit /b 1
)
popd
echo   [OK]   Frontend built -^> frontend\dist\
exit /b 0

rem Fix incomplete node_modules copied from non-Windows machines:
rem native bindings (typescript/rolldown/lightningcss) are missing.
:ensure_platform_deps
set "MISSING_DEPS="
if not exist "%FRONTEND_DIR%\node_modules\@typescript\typescript-win32-x64" set "MISSING_DEPS=!MISSING_DEPS! @typescript/typescript-win32-x64"
if not exist "%FRONTEND_DIR%\node_modules\@rolldown\binding-win32-x64-msvc" set "MISSING_DEPS=!MISSING_DEPS! @rolldown/binding-win32-x64-msvc"
if not exist "%FRONTEND_DIR%\node_modules\lightningcss-win32-x64-msvc" set "MISSING_DEPS=!MISSING_DEPS! lightningcss-win32-x64-msvc"
if not defined MISSING_DEPS (
    exit /b 0
)
echo   [WARN] node_modules seems copied from another platform, missing Windows native bindings.
echo         Installing:%MISSING_DEPS%
pushd "%FRONTEND_DIR%"
call npm install --no-save%MISSING_DEPS%
if errorlevel 1 (
    echo   [ERROR] Failed to install platform bindings.
    popd
    exit /b 1
)
popd
echo   [OK]   Platform bindings installed.
exit /b 0

:build_server
echo [Step] Building server (wisp.exe)...
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"
pushd "%PROJECT_ROOT%"
set "CGO_ENABLED=1"
call go build -o "%BIN_DIR%\wisp.exe" .
if errorlevel 1 (
    echo   [ERROR] Server build failed.
    popd
    exit /b 1
)
popd
for %%F in ("%BIN_DIR%\wisp.exe") do echo   [OK]   Server built -^> bin\wisp.exe (%%~zF bytes)
exit /b 0

:build_agent
echo [Step] Building agent (current platform)...
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"
pushd "%AGENT_DIR%"
set "CGO_ENABLED=0"
rem -H windowsgui = GUI subsystem: no console black window when double-clicked
set "LDFLAGS=-s -w -H windowsgui"
call go build -ldflags="!LDFLAGS!" -trimpath -o "%BIN_DIR%\agent.exe" .
if errorlevel 1 (
    echo   [ERROR] Agent build failed.
    popd
    exit /b 1
)
popd
for %%F in ("%BIN_DIR%\agent.exe") do echo   [OK]   Agent built -^> bin\agent.exe (%%~zF bytes)
exit /b 0

:build_agent_all
echo [Step] Cross-compiling agent for all platforms...
if not exist "%BIN_DIR%" mkdir "%BIN_DIR%"
pushd "%AGENT_DIR%"

set "PLATFORMS=windows/amd64/exe windows/arm64/exe linux/amd64/linux linux/arm64/linux darwin/amd64/darwin darwin/arm64/darwin"
for %%P in (%PLATFORMS%) do (
    for /f "tokens=1,2,3 delims=/" %%a in ("%%P") do (
        set "GOOS=%%a"
        set "GOARCH=%%b"
        if "%%c"=="exe" (
            rem Windows targets: GUI subsystem so the agent shows no console
            set "EXT=.exe"
            set "GUI=-H windowsgui"
        ) else (
            set "EXT="
            set "GUI="
        )
        call go build -ldflags="-s -w !GUI!" -trimpath -o "%BIN_DIR%\agent_%%a_%%b!EXT!" .
        if errorlevel 1 (
            echo   [ERROR] Build %%a/%%b failed.
            popd
            exit /b 1
        )
        for %%F in ("%BIN_DIR%\agent_%%a_%%b!EXT!") do echo   [OK]   %%a/%%b -^> agent_%%a_%%b!EXT! (%%~zF bytes)
    )
)
popd
exit /b 0

:clean
echo [Step] Cleaning build artifacts...
if exist "%BIN_DIR%" (
    rmdir /s /q "%BIN_DIR%"
    echo   [OK]   Removed bin\
)
if exist "%FRONTEND_DIR%\dist" (
    rmdir /s /q "%FRONTEND_DIR%\dist"
    echo   [OK]   Removed frontend\dist\
)
exit /b 0

:usage
echo Commands:
echo   all          Build frontend + server + agent (default)
echo   frontend     Build frontend only
echo   server       Build frontend + server
echo   agent        Build agent for current platform
echo   agent-all    Cross-compile agent for all 6 platforms
echo   clean        Remove build artifacts
echo   help         Show this help
exit /b 0

:done
echo.
echo  Done.
endlocal
exit /b 0
