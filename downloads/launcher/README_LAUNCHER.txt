WinLab Lanzador - Uso rapido

1) Doble clic en WinLab_Launcher.cmd (abre la interfaz).
2) Elegi un perfil: Equilibrado / Ultra seguro / Con red.
3) Arrastra un archivo o pega una URL. El reporte se abre al finalizar.

Incluye:
- Licencia local con archivo license.json (ejemplo en downloads/license.sample.json).
- Boton "Buscar actualizacion" (usa WinLab_Update.ps1 y registra SHA en C:\WinLab\logs\update.log).
- Doctor y acceso rapido a logs.

Rutas importantes:
- Reportes: C:\WinLab_Outbox
- Logs: C:\WinLab\logs
- Licencia: C:\ProgramData\WinLab\license.json

Requisitos:
- Windows 10/11 Pro, Enterprise o Education.
- Windows Sandbox habilitado.

Notas:
- GitHub Pages es informativo: el Sandbox no corre en la web.
- Extrae el paquete completo antes de ejecutar.
- Si falta Windows Sandbox, habilitalo (PowerShell admin):
  Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart
