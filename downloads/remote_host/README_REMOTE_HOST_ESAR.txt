WINLAB - LABORATORIO REMOTO (GUIA RAPIDA)

Objetivo
- Usar WinLab desde el celular sin exponer RDP a Internet.
- El sandbox corre en Windows; el celular solo controla el host remoto.

Requisitos
- Windows 10/11 Pro, Enterprise o Education.
- Windows Sandbox habilitado (Containers-DisposableClientVM).
- Conexion estable a Internet.
- Cuenta dedicada para el laboratorio.

Paso a paso (host Windows)
1) Instala WinLab y confirma que abre el launcher.
2) Instala Tailscale en el host (VPN privada).
3) Inicia sesion con tu cuenta y verifica la IP Tailscale (100.x).
4) Ejecuta RemoteHost_Doctor.ps1 para validar el host.

Paso a paso (celular)
1) Instala Tailscale en iPhone/Android.
2) Inicia sesion en la misma cuenta de Tailscale.
3) Instala "Escritorio remoto" de Microsoft.
4) Conectate al host usando la IP Tailscale.
5) Abri WinLab y corre el analisis.

Seguridad basica
- NO abras el puerto RDP en el router ni en la nube.
- Usa contrasena fuerte y usuario dedicado.
- Bloqueo de pantalla y actualizaciones al dia.
- Si podes, activa BitLocker.

Archivos en esta carpeta
- RemoteHost_Doctor.ps1 (diagnostico del host)
- RemoteHost_Hardening.txt (checklist de hardening)

Notas
- WinLab no corre en iPhone o Android. Solo se opera remoto.
- Si preferis, podes pedir analisis asistido por WhatsApp.
