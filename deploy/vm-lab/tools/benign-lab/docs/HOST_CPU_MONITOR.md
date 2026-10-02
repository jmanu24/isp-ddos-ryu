# CPU de hosts — DDOS PUCP LAB

El dashboard incorpora CPU de hosts con porcentaje total, gráfica temporal, media, máximo, última muestra y estado de conexión. Origen en vivo o ejecución seleccionada. Ventanas de 5/15/60 minutos; historial SQLite acotado a seis horas y persistente ante reinicios.

ESXi 192.168.18.135: govc metric.sample cpu.usage.average, instancia agregada vacía, escala /100. Intervalos reales de 20 segundos, deduplicados por timestamp; no se suman porcentajes de procesadores lógicos. Se conservan instancias individuales en per_cpu_pct. Windows 192.168.18.45: GetSystemTimes, diferencia kernel+user menos idle, cada 5 segundos. Incluye CPU de todo Windows, VMware y otras aplicaciones. No requiere psutil ni contraseña nueva.

Windows expone /resources solo en el backend loopback existente 127.0.0.1:18781, con su token y túnel SSH actuales. Si el túnel o el backend cae, el dashboard marca desconexión y deja huecos. ESXi usa .govc.env privado mediante el shell, sin mostrar credenciales. Las muestras viejas no se presentan como lecturas actuales.

Configuración host_monitor en lab.connected.yaml: retention_s y lista hosts; ESXi requiere name, adapter=esxi, object del inventario, govc_env y poll_s=20. Windows requiere name, adapter=workstation, config_file privado del backend y poll_s=5. Consultar config/host-monitor.example.yaml y adaptar las rutas si cambia el checkout. El archivo de ejemplo se fusiona con la configuración del laboratorio, no la sustituye.

API autenticada: GET /api/resources?minutes=5&after=0 y GET /api/runs/{id}/resources?after=0. Las nuevas ejecuciones reales guardan host_metrics.jsonl dentro del ZIP exportado. Las ejecuciones anteriores solo mostrarán CPU si existía una captura conservada para ese intervalo; no se reconstruyen datos inexistentes. Campos: host, platform, timestamp UTC Unix, received_at, interval_s, cpu_pct (0–100), logical_cpus, métricas adicionales cuando disponibles, cursor id y metrics_kind=host_cpu.

Reinicio Windows: el lanzador existente inicia workstation_bridge.py actualizado. Para aplicar a un backend ya abierto, reiniciar solo ese proceso; mantener el túnel y las VMs. En el control reiniciar benign-lab-web solo sin experimentos activos. Las credenciales y rutas privadas permanecen fuera del proyecto distribuido.

Se conserva BENIGN_V1 como nombre del perfil científico. Cambia únicamente la identidad visible de la plataforma a DDOS PUCP LAB. No cambian semillas, plan_hash, payload ni ground truth.

CPU total del host no sustituye CPU Ready por VM ni CPU dentro de cada invitado; esta implementación permite comparar presión global entre ambos hosts.
