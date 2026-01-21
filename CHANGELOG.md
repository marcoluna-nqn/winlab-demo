# Changelog

## v0.8.2 - 2026-01-20
- **UX**: menu contextual "Analizar con WinLab" para archivos y accesos URL, con launcher integrado.
- **Host Remoto**: servicio local opcional con clave API, limite de solicitudes y docs para uso desde celular.
- **Reportes**: resumen para humanos en HTML/JSON + samples actualizados.

## v0.8.1 - 2026-01-20
- **Launcher**: selector de preset, soporte archivo/URL, staging en `C:\WinLab_Pack` y apertura de reporte al finalizar.
- **Logs**: centralizados en `C:\WinLab\logs` y mapeo `C:\WinLabLogs` dentro del Sandbox.
- **InsideLab**: script corregido y reportes normalizados con resumen ejecutivo + detalle técnico.
- **Presets**: AUTO actualizados con mapeo de logs.
- **Docs/Samples**: guía y ejemplos en ES-AR, sin placeholders.
- **QA/Release**: smoke tests validan placeholders y contenido del instalador.

## v0.8.0 - 2026-01-19
- **InsideLab**: AutoDecision reforzado (señales fuertes fuerzan INCONCLUSO) y reporte con significado + timeline.
- **Reportes**: HTML vendible con semáforo y JSON schemaVersion 1.0.
- **CLI**: WinLab.ps1/WinLab.cmd alineados + aliases `scan-file` y `analyze-url`.
- **Samples**: ejemplos HTML/JSON actualizados y marcados como simulados.
- **Docs**: guía y FAQ sin sobreventa, threat model + troubleshooting.
- **Build/QA**: smoke tests ampliados para validar samples y contenido del instalador.

## v0.7.0 - 2026-01-19
- **CLI (terminal)**: se agregó `WinLab.ps1` + `WinLab.cmd` para lanzar el laboratorio desde PowerShell/CMD y pasar un archivo o un link.
- **Triage de links (Networked)**: el reporte puede incluir DNS/TLS/redirects, headers relevantes y una recomendación simple.
- **Artefactos de descarga**: durante sesiones con URL, WinLab detecta descargas dentro del Sandbox, calcula SHA-256 y las somete a escaneo.
- **Telemetría mínima útil**: baseline y delta de procesos y conexiones TCP para aportar contexto sin ruido.
- **Reporte v1.1**: JSON ampliado con `autoDecision` y `urlAnalysis` (cuando aplica); HTML con secciones más completas.
- **Setup**: accesos directos incluyen `WinLab (CLI)`.

## v0.6.1 - 2026-01-19
- **Presets coherentes**: accesos directos y presets alineados con **Balanced / UltraSecure / Networked**.
- **UltraSecure con outbox**: mantiene red deshabilitada y restricciones duras, pero exporta reporte al host.
- **Flujo de archivos seguro (RO → RW)**: el archivo se toma de Descargas del host (mapeado ReadOnly) y se copia a carpeta interna antes de escanear.
- **Pipeline Defender más robusto**: actualización de firmas con fallback (`Update-MpSignature` → `MpCmdRun -SignatureUpdate`).
- **Reporte v1.0**: JSON con `schemaVersion` y HTML con semáforo + recomendación accionable.
- **Sitio**: se actualizó el enlace de descarga y se refrescaron ejemplos.

