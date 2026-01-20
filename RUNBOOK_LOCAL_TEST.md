# Runbook de pruebas locales

## Pruebas de sitio
1. `python -m http.server 8000` en root.
2. Abrir `http://localhost:8000` y validar links.

## Pruebas de Setup
1. Descomprimir `downloads/WinLab_Setup_vX.Y.Z.zip`.
2. Ejecutar `WinLab_Setup.cmd`.
3. Validar accesos directos y CLI.

## Pruebas de laboratorio
- UltraSecure: ejecutar `WinLab.cmd scan -Path <archivo>` y verificar reportes en outbox.
- Networked: ejecutar `WinLab.cmd url -Url <url>` y verificar triage + descargas + Auto-Decision.

## Build y smoke tests
- `./build.ps1`
- `./smoke_tests.ps1`
