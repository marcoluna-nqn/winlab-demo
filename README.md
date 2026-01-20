# WinLab

WinLab es un laboratorio descartable para analizar archivos o URLs sospechosas usando Windows Sandbox y Microsoft Defender. No es un antivirus propio: reduce el riesgo aislando el proceso y generando reportes claros.

## Instalacion (recomendada)
1) Ejecuta el instalador `dist/WinLab_Installer_0.8.0.exe`.
2) Se crean accesos directos en Escritorio y Menu Inicio.
3) Abri WinLab y elegi un preset.

## Uso rapido
- Abri el launcher y elegi Equilibrado, Ultra seguro o Con red.
- Arrastra un archivo o pega una URL.
- El reporte se abre al finalizar.
- Reportes en `C:\WinLab_Outbox` y logs en `C:\WinLab\logs`.

## Diagnostico
- Acceso directo: "WinLab (Doctor)".
- CLI: `WinLab.ps1 doctor`.
- Reporte: `C:\WinLab\logs\doctor.txt`.

## Requisitos
- Windows 10/11 Pro, Enterprise o Education.
- Windows Sandbox habilitado.
- Virtualizacion activada en BIOS/UEFI.

## Contenido del repo
- Sitio (GitHub Pages): `index.html` + `docs/` + `assets/`.
- Instalador ZIP (legacy): `downloads/WinLab_Setup_v0.8.0.zip`.
- Launcher: `downloads/launcher/WinLab_Launcher.cmd`.
- CLI: `tools/cli/WinLab.ps1` y `tools/cli/WinLab.cmd`.

## Build y QA
- Build reproducible: `./build.ps1` o `./build_release.ps1`
- Smoke tests: `./smoke_tests.ps1`

Para ajustes avanzados ver `PROMPT_CODEX_XHIGH.md`.
