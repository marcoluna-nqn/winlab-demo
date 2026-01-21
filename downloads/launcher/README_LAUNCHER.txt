WinLab Lanzador - Uso rapido

1) Doble clic en WinLab_Launcher.cmd
2) O ejecuta desde terminal: WinLab_Launcher.cmd Equilibrado

El lanzador permite:
- Elegir perfil (Equilibrado / Ultra seguro / Con red).
- Analizar un archivo (arrastrar y soltar o pasar ruta) o una URL.
- Generar el reporte en C:\WinLab_Outbox y abrirlo al finalizar.

Requisitos:
- Windows 10/11 Pro, Enterprise o Education.
- Windows Sandbox habilitado.

Notas:
- GitHub Pages es informativo: el Sandbox no corre en la web.
- Extrae el paquete completo antes de ejecutar.
- Si falta Windows Sandbox, habilitalo (PowerShell administrador):
  Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart
- Logs en C:\WinLab\logs
