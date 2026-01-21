WINLAB - LABORATORIO REMOTO (GUIA RAPIDA)

Objetivo
- Usar WinLab desde el celular sin exponer RDP a Internet.
- El sandbox corre en Windows; el celular solo controla el host remoto.
- Servicio local opcional para recibir URL o archivos con clave API.

Requisitos
- Windows 10/11 Pro, Enterprise o Education.
- Windows Sandbox habilitado (Containers-DisposableClientVM).
- Conexion estable a Internet.
- Cuenta dedicada para el laboratorio.

Opcion A (recomendada): acceso remoto
1) Instala WinLab y confirma que abre el launcher.
2) Instala Tailscale en el host y en el celular.
3) Conectalos a la misma red segura (VPN).
4) Usa Escritorio remoto y entra por la IP de Tailscale.
5) Ejecuta WinLab y genera el reporte.

Opcion B (servicio local WinLab Host Remoto)
1) Ejecuta Install_RemoteHost.ps1 (administrador).
2) Edita C:\ProgramData\WinLab\remote_host\config.json y cambia claveApi.
3) Inicia el servicio con Start_RemoteHost.ps1.
4) Envia solicitudes al host por localhost o LAN (si lo habilitas).
5) Agrega el encabezado obligatorio: X-WINLAB-KEY con tu claveApi.

Rutas
- GET http://127.0.0.1:17171/estado
- POST http://127.0.0.1:17171/api/analizar-url
  Cuerpo JSON: {"url": "https://sitio.com"}
- POST http://127.0.0.1:17171/api/analizar-archivo
  Cuerpo JSON: {"nombreArchivo": "archivo.exe", "contenidoBase64": "BASE64_DEMO"}
 - Logs: C:\WinLab\logs\remote_host.log

Seguridad basica
- NO abras el puerto RDP en el router ni en la nube.
- Por defecto el servicio escucha solo en 127.0.0.1.
- Si lo expones en LAN, usa VPN y clave fuerte.
- Contrasena fuerte y usuario dedicado.
- Bloqueo de pantalla y actualizaciones al dia.
- Si podes, activa BitLocker.

Archivos en esta carpeta
- WinLab_RemoteHost.ps1 (servicio local)
- Install_RemoteHost.ps1 / Start_RemoteHost.ps1 / Stop_RemoteHost.ps1 / Uninstall_RemoteHost.ps1
- remote_host_config.json (config base)
- RemoteHost_Doctor.ps1 (diagnostico del host)
- RemoteHost_Hardening.txt (checklist de hardening)

Notas
- WinLab no corre en iPhone o Android. Solo se opera remoto.
- Si preferis, podes pedir analisis asistido por WhatsApp.
