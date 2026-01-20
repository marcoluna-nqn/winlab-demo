# WinLab

WinLab es un laboratorio descartable basado en Windows Sandbox y Microsoft Defender. No es un antivirus propio: el valor es el aislamiento, el pipeline y el reporte.

## Contenido
- Sitio (GitHub Pages): `index.html` + `docs/` + `assets/`.
- Instalador: `downloads/WinLab_Setup_vX.Y.Z.zip`.
- CLI: `WinLab.ps1` y `WinLab.cmd` (ver `tools/cli/`).

## Caracteristicas clave
- Presets: Balanced / UltraSecure / Networked.
- Flujo seguro: copia ReadOnly -> carpeta interna antes de escanear.
- Pipeline Defender: update firmas + escaneo + evidencia (hash, MOTW, firma).
- Reportes: HTML/JSON/TXT con semaforo y AutoDecision.

## Build y pruebas
- Build reproducible: `./build.ps1`
- Smoke tests: `./smoke_tests.ps1`

Para productizar o ajustar el flujo interno ver `PROMPT_CODEX_XHIGH.md`.
