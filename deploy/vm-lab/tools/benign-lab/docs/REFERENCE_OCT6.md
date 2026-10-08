# Referencia de las pruebas del 6 octubre

Ejecuciones: 20261006T165656-fec872bd y 20261006T173211-42b46757. Plan semilla 2: 18aa3c08e732aa6ac773f09538ccabe6df629ee3effb8d02b0d191f2538dbd1c. Payload global observado 95.42% y 94.91% respectivamente.

Se restaura classic como perfil por defecto y se retira peering_pool de la configuración activa: todas las fuentes peer-flow* vuelven a 10.30.0.2. El segundo peer conserva su BGP y administración, sin flujos de esta prueba. El botón de referencia selecciona este plan, laboratorio, B0, baseline y classic. Capacidades, destinos y start_lead_s coinciden con las capturas antiguas.

Se conservan las IP/sesiones dinámicas Fixed actuales y la clasificación estricta v2. La lógica de envío conserva la referencia histórica; restaurar estados completed para cuotas parciales no incrementaría la entrega. El código del 6 octubre por fecha corresponde a 350a49d, pero el run.json no fija commit y no se presenta como prueba exacta de revisión.

La ubicación física Peering sigue siendo Workstation; no se restaura su antigua VM ESXi ni se crean duplicados. Tampoco se recupera el estado temporal de red, carga, ARP o cachés del momento histórico. Por ello se restaura la configuración experimental identificada, sin garantizar repetir porcentajes superiores al 90%.
