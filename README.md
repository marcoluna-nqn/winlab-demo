# WinLab

WinLab es un laboratorio descartable basado en Windows Sandbox y Microsoft Defender. No es un antivirus propio: el valor es el aislamiento, el pipeline y el reporte.

## Contenido
- Sitio (GitHub Pages): `index.html` + `docs/` + `assets/`.
- Instalador: `downloads/WinLab_Setup_vX.Y.Z.zip`.
- Lanzador: `downloads/launcher/WinLab_Launcher.cmd`.
- CLI: `WinLab.ps1` y `WinLab.cmd` (ver `tools/cli/`).

## Características clave
- Presets: Equilibrado (Balanced) / Ultra seguro (UltraSecure) / Con red (Networked).
- Flujo seguro: copia ReadOnly -> carpeta interna antes de escanear.
- Pipeline Defender: actualización de firmas + escaneo + evidencia (hash, MOTW, firma).
- Reportes: HTML/JSON/TXT con resumen ejecutivo, detalle técnico y AutoDecision.

## Build y pruebas
- Build reproducible: `./build.ps1` o `./build_release.ps1`
- Smoke tests: `./smoke_tests.ps1`

## Uso rápido
1) Extraé el pack completo.
2) Ejecutá `downloads\launcher\WinLab_Launcher.cmd` y elegí preset.
3) Reportes en `C:\WinLab_Outbox` y logs en `C:\WinLab\logs`.

Para productizar o ajustar el flujo interno ver `PROMPT_CODEX_XHIGH.md`.
