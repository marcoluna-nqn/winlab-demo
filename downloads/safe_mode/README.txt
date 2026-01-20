Safe Mode Helper - WinLab
==========================

Objetivo
- Asistente opcional para entrar/salir de Modo Seguro en Windows cuando necesitas aislar un equipo antes de abrir WinLab.
- Requiere ejecutar como Administrador. No hace cambios sin tu confirmación.

Uso rápido
1) Ejecuta SafeMode_Helper.cmd como Administrador.
2) Elige una opción:
   - Ver pasos manuales (no toca nada).
   - Abrir msconfig.
   - Aplicar Modo Seguro (bcdedit /set {current} safeboot minimal) con confirmación.
   - Revertir Modo Seguro (bcdedit /deletevalue {current} safeboot) con confirmación.
3) Reinicia cuando el asistente lo indique.

Advertencias
- Modo Seguro deshabilita drivers/servicios; úsalo solo si sabes lo que haces.
- Si no tienes permisos de Administrador, el script mostrará un aviso y no aplicará cambios.
- Para volver al modo normal, usa la opción de revertir o ejecuta manualmente:
  bcdedit /deletevalue {current} safeboot

Más contexto
- WinLab sigue requiriendo Windows Sandbox habilitado. Modo Seguro es solo para aislar antes de ejecutar.
- No automatizamos nada desde la web: descargas este helper y lo ejecutas localmente.
