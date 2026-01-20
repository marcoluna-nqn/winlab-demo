WinLab Launcher - Uso rapido

1) Doble click en WinLab_Launcher.cmd
2) O ejecuta desde terminal: WinLab_Launcher.cmd Balanced

Presets disponibles:
- Balanced (default)
- UltraSecure
- Networked

Que hace:
- Verifica Windows Sandbox (Containers-DisposableClientVM).
- Crea C:\WinLab_Inbox y C:\WinLab_Outbox si no existen.
- Copia el pack a C:\WinLab_Pack (staging sin espacios).
- Genera presets AUTO y abre el preset elegido.

Notas:
- GitHub Pages es estatico: el Sandbox no corre en la web.
- Extrae el pack completo antes de ejecutar.
- Si falta Windows Sandbox, habilitalo (PowerShell Admin):
  Enable-WindowsOptionalFeature -Online -FeatureName Containers-DisposableClientVM -All -NoRestart
