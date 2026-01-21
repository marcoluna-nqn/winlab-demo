# Publish Checklist (Go Live)

1) Run `scripts/publish.ps1` and confirm it exits with code 0.
2) Confirm `dist/winlab_site.zip` and `dist/WinLab_ProductPack_<ver>.zip` exist.
3) Confirm `dist/SHA256SUMS.txt` matches the generated zips.
4) Verify `assets/config.js` has real payment links or WhatsApp fallback.
5) Check `pricing.html` shows plans and delivery/requisitos sections.
6) Check `index.html` CTA: "Descargar y ejecutar" and "Ver planes".
7) Validate launcher on a clean Windows 10/11 Pro host with Sandbox enabled.
8) Confirm GitHub release exists with assets attached.
9) Confirm GitHub Pages is set to main /(root) and site loads.
10) Verify downloads link to `downloads/WinLab_Setup_v1.0.0.zip`.
