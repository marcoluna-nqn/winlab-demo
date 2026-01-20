# Changelog

## v0.8.1 - 2026-01-20

- **Launcher**: staging en `C:\WinLab_Pack` y presets AUTO generados con rutas robustas.
- **Presets**: mapeos consistentes para pack/inbox/outbox y comandos con rutas sin espacios.
- **Web**: CTA "Descargar y ejecutar", pricing con requisitos y entrega, y microcopy honesto.
- **Docs**: modelo de amenaza, que no cubre y politica de uso seguro.
- **QA/Release**: smoke tests ampliados y build_release para paquetes + SHA256.

## v0.8.0 â€“ 2026-01-19

- **InsideLab**: AutoDecision reforzado (seÃ±ales fuertes fuerzan INCONCLUSO) y reporte con significado + timeline.
- **Reportes**: HTML vendible con semÃ¡foro y JSON schemaVersion 1.0.
- **CLI**: WinLab.ps1/WinLab.cmd alineados + aliases `scan-file` y `analyze-url`.
- **Samples**: ejemplos HTML/JSON actualizados y marcados como simulados.
- **Docs**: guÃ­a y FAQ sin sobreventa, threat model + troubleshooting.
- **Build/QA**: smoke tests ampliados para validar samples y contenido del instalador.

## v0.7.0 â€“ 2026â€‘01â€‘19

- **CLI (terminal)**: se agregÃ³ `WinLab.ps1` + `WinLab.cmd` para lanzar el laboratorio desde PowerShell/CMD y pasar un archivo o un link.
- **Triage de links (Networked)**: el reporte puede incluir DNS/TLS/redirects, headers relevantes y una recomendaciÃ³n simple.
- **Artefactos de descarga**: durante sesiones con URL, WinLab detecta descargas dentro del Sandbox, calcula SHAâ€‘256 y las somete a escaneo.
- **TelemetrÃ­a mÃ­nima Ãºtil**: baseline y delta de procesos y conexiones TCP (limitado a top N) para aportar contexto sin â€œruidoâ€.
- **Reporte v1.1**: JSON ampliado con `autoDecision` y `urlAnalysis` (cuando aplica); HTML con secciones mÃ¡s completas.
- **Setup**: accesos directos incluyen `Winâ€‘Lab (CLI)`.

## v0.6.1 â€“ 2026â€‘01â€‘19

- **Presets coherentes**: accesos directos y presets alineados con **Balanced / UltraSecure / Networked**.
- **UltraSecure con outbox**: mantiene red deshabilitada y restricciones duras, pero exporta reporte al host para UX (sin abrir nada dentro del Sandbox).
- **Flujo de archivos seguro (RO â†’ RW)**: el archivo se toma de <b>Descargas</b> del host (mapeado ReadOnly) y se copia a una carpeta interna antes de escanear.
- **Pipeline Defender mÃ¡s robusto**: actualizaciÃ³n de firmas con fallback (`Updateâ€‘MpSignature` â†’ `MpCmdRun -SignatureUpdate`).
- **Reporte v1.0 consolidado**: JSON con `schemaVersion` y HTML con semÃ¡foro + recomendaciÃ³n accionable.
- **Sitio**: se actualizÃ³ el enlace de descarga a <code>WinLab_Setup_v0.6.1.zip</code> y se refrescaron los ejemplos.

