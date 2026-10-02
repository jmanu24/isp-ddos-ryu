# Tráfico real por elemento

La pestaña **Tráfico por elemento** muestra RX y TX en Mbps, selección de interfaz y volumen de la ventana. Incluye las 23 VMs, el control node, las cinco UE en sus namespaces y los diez suscriptores macvlan. Los contadores son de Linux: incluyen tráfico de gestión, cabeceras y retransmisiones; no equivalen al payload de las aplicaciones. No se suman elementos porque una misma transferencia cruza varios nodos.

Los recolectores leen `/sys/class/net` cada 5 segundos. Las tasas usan el reloj monotónico del origen. Un reinicio de contadores o pérdida de conexión produce un hueco, no un pico ni un cero ficticio. La conexión SSH conserva la verificación de las claves conocidas. No se modifica el pipeline, el encaminamiento ni la configuración de las interfaces.

`config/lab.connected.yaml: traffic_monitor` define host, usuario, variable de credencial, archivo de claves conocidas, namespaces e interfaz preferida por VM. Ajusta esa interfaz si cambia la topología. Las credenciales permanecen en el archivo privado de entorno del servicio. `scripts/install_interface_probes.py` instala el sampler desde el inventario del repositorio usando las credenciales existentes; ejecútalo desde el control node con el Python del entorno de la aplicación.

El historial global retiene 6 horas en SQLite dentro de BENIGN_DATA/traffic. Durante las nuevas ejecuciones reales se guardan muestras en `interface_metrics.jsonl`, incluidas en la exportación. Los experimentos antiguos y las demostraciones no tienen mediciones de interfaces. La pantalla permite cambiar entre el laboratorio en vivo y la ejecución seleccionada en Control de ejecución.

API autenticada: GET /api/traffic?minutes=5&after=0 y GET /api/runs/{id}/interface-traffic?after=0. Cada muestra identifica nodo, elemento, dominio, interfaz, timestamp, RX/TX, paquetes, descartes y errores. BENIGN_V1, semillas, benign_plan.json, plan_hash y ground truth de 5 segundos permanecen iguales.
