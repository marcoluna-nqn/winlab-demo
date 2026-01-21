# WinLab

WinLab es un laboratorio descartable para analizar archivos o URLs sospechosas usando Windows Sandbox y Microsoft Defender. No es un antivirus propio: reduce el riesgo aislando el proceso y generando reportes claros.

## Instalacion (recomendada)
1) Ejecuta el instalador `dist/WinLab_Installer_1.0.0.exe`.
2) Se crean accesos directos en Escritorio y Menu Inicio.
3) Abri WinLab (lanzador con UI) y elegi un perfil.

## Uso rapido
- Abri el lanzador y elegi Equilibrado, Ultra seguro o Con red.
- Arrastra un archivo o pega una URL.
- El reporte se abre al finalizar.
- Reportes en `C:\WinLab_Outbox` y logs en `C:\WinLab\logs`.

## Licencia
- Archivo `C:\ProgramData\WinLab\license.json` firmado (ejemplo en `downloads/license.sample.json`).
- Estado visible en el lanzador. Si falta, pedila por WhatsApp y pegala en esa ruta.

## Actualizaciones
- Ejecuta `tools/cli/WinLab_Update.ps1` o usa el botón "Buscar actualización" del lanzador.
- Descarga el instalador nuevo desde GitHub Releases y muestra el hash SHA256 en `C:\WinLab\logs\update.log`.

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
- Instalador ZIP (legado): `downloads/WinLab_Setup_v1.0.0.zip`.
- Lanzador: `downloads/launcher/WinLab_Launcher.cmd`.
- CLI: `tools/cli/WinLab.ps1` y `tools/cli/WinLab.cmd`.

## Compilacion y QA
- Compilacion reproducible: `./build.ps1` o `./build_release.ps1`
- Pruebas rapidas: `./smoke_tests.ps1`

Para ajustes avanzados ver `PROMPT_CODEX_XHIGH.md`.
