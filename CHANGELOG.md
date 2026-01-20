# Changelog

## v0.8.0 – 2026-01-19

- **InsideLab**: AutoDecision reforzado (señales fuertes fuerzan INCONCLUSO) y reporte con significado + timeline.
- **Reportes**: HTML vendible con semáforo y JSON schemaVersion 1.0.
- **CLI**: WinLab.ps1/WinLab.cmd alineados + aliases `scan-file` y `analyze-url`.
- **Samples**: ejemplos HTML/JSON actualizados y marcados como simulados.
- **Docs**: guía y FAQ sin sobreventa, threat model + troubleshooting.
- **Build/QA**: smoke tests ampliados para validar samples y contenido del instalador.

## v0.7.0 – 2026‑01‑19

- **CLI (terminal)**: se agregó `WinLab.ps1` + `WinLab.cmd` para lanzar el laboratorio desde PowerShell/CMD y pasar un archivo o un link.
- **Triage de links (Networked)**: el reporte puede incluir DNS/TLS/redirects, headers relevantes y una recomendación simple.
- **Artefactos de descarga**: durante sesiones con URL, WinLab detecta descargas dentro del Sandbox, calcula SHA‑256 y las somete a escaneo.
- **Telemetría mínima útil**: baseline y delta de procesos y conexiones TCP (limitado a top N) para aportar contexto sin “ruido”.
- **Reporte v1.1**: JSON ampliado con `autoDecision` y `urlAnalysis` (cuando aplica); HTML con secciones más completas.
- **Setup**: accesos directos incluyen `Win‑Lab (CLI)`.

## v0.6.1 – 2026‑01‑19

- **Presets coherentes**: accesos directos y presets alineados con **Balanced / UltraSecure / Networked**.
- **UltraSecure con outbox**: mantiene red deshabilitada y restricciones duras, pero exporta reporte al host para UX (sin abrir nada dentro del Sandbox).
- **Flujo de archivos seguro (RO → RW)**: el archivo se toma de <b>Descargas</b> del host (mapeado ReadOnly) y se copia a una carpeta interna antes de escanear.
- **Pipeline Defender más robusto**: actualización de firmas con fallback (`Update‑MpSignature` → `MpCmdRun -SignatureUpdate`).
- **Reporte v1.0 consolidado**: JSON con `schemaVersion` y HTML con semáforo + recomendación accionable.
- **Sitio**: se actualizó el enlace de descarga a <code>WinLab_Setup_v0.6.1.zip</code> y se refrescaron los ejemplos.
