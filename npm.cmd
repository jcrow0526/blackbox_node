@echo off
setlocal

set "NODE_EXE=C:\Program Files\nodejs\node.exe"
set "NPM_CLI_JS=C:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js"

if not exist "%NODE_EXE%" (
  echo node.exe not found at "%NODE_EXE%"
  exit /b 1
)

if not exist "%NPM_CLI_JS%" (
  echo npm-cli.js not found at "%NPM_CLI_JS%"
  exit /b 1
)

"%NODE_EXE%" "%NPM_CLI_JS%" %*
