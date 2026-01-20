# Acceptance Checklist (Producto)

- [x] Sitio en root: `index.html`, `docs/`, `assets/`, `downloads/`.
- [x] `downloads/` contiene el ultimo `WinLab_Setup_vX.Y.Z.zip` y samples.
- [x] CLI disponible: `WinLab.cmd` y `WinLab.ps1` instalados por Setup.
- [x] Presets: UltraSecure/Balanced/Networked disponibles y documentados.
- [x] InsideLab productivo: update firmas, RO->RW, scan, evidencias, reportes.
- [x] JSON: `schemaVersion=1.0` y campos obligatorios (hash, firmas, duracion, preset, resultado).
- [x] HTML vendible con semaforo + evidencias + explicacion de INCONCLUSO.
- [x] Auto-Decision implementada y visible en reporte.
- [x] `build.ps1` genera `/dist` + hashes.
- [x] `smoke_tests.ps1` pasa en entorno de CI/local.
- [x] Docs: threat model, limitaciones, FAQ, troubleshooting.
- [x] Sin claims falsos: copy revisado.
