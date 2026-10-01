# Despliegue en el laboratorio real

La entrega adapta el ZIP original, sin cambiar BENIGN_V1. No se ha accedido a ninguna VM del laboratorio: no se proporcionaron hosts SSH ni credenciales. Las conexiones reales del laboratorio no están certificadas.

## Inventario confirmado por la conversación

23 VMs en ESXi; Mobile con cinco UE; Fixed con diez abonados lógicos, BNG accel-ppp, FreeRADIUS y DHCP/IPoE; cinco `ent-site-*`; generador Peering detrás del `peer-router`. Destino central `10.55.0.100`. Backbones Mobile `10.91.0.0/30`, Fixed `10.92.0.0/30`, Peering `10.93.0.0/30`. Estas redes son referencias, no gateways asignados por la herramienta.

## Configuración

Copiar `config/lab.real.yaml` a `config/lab.yaml`. Los campos `null` requieren información real. Mantener `require_explicit_mapping: true`. El archivo de ejemplo anterior sigue siendo ilustrativo y la demo sigue usando loopback.

Completar:

| Campo | Información requerida |
|---|---|
| `capacity_mbps` | Capacidad calibrada de cada dominio, en Mbps |
| `host`, `user`, `port`, `identity_file` | Acceso SSH de gestión; la IP de gestión no será origen del tráfico |
| `namespace` | Namespace existente; `ue1` puede mapearse a `ue` si así se llama la primera UE |
| `source_ip`, `interface` | IP de datos ya asignada e interfaz de salida dentro del contexto del agente |
| `expected_gateway` | Siguiente salto de datos cuando se quiera exigir uno; obligatorio en Peering |
| `agent_path`, `python` | Rutas existentes en cada VM |
| `configured` | Cambiar a `true` después de completar la entrada |
| `targets.ent-site-*.host` | IPs de datos de cada receptor Enterprise |
| `session_id`, `access_mode` | Sesión IPoE activa y modo de ejecución Fixed |

Mobile usa `netns` o `ssh_netns`; ejecuta `ip netns exec ueX /usr/bin/python3 ... worker`, opcionalmente con `sudo -n`. Sus sockets se enlazan a la IP UE indicada. El laboratorio proporciona el camino DU/CU/5GC.

Fixed ofrece dos modos:

- `ipoe_namespace`: `adapter: ssh_netns` o `netns`, namespace e IP de una sesión activa.
- `ipoe_bound`: `adapter: ssh` o `local`, IP de abonado asignada a una interfaz del host `subscriber`. Cada IP/contexto tiene su agente, aunque comparta host. Para VLAN/macvlan/interfaces dedicadas, declarar la interfaz correspondiente.

`session_id` se conserva como referencia del operador. La herramienta no consulta accel-ppp/FreeRADIUS, no inicia DHCP ni crea sesiones. Una ruta válida no demuestra autenticación ni que un abonado esté activo en el BNG. Si las IPs de abonado no son locales al contexto de ejecución, el preflight falla. No mapear diez abonados a la misma IP si se requiere distinguirlos en capturas.

Enterprise ejecuta en cada `ent-site-*` mediante SSH, local o namespace y conserva los destinos intersite del plan. Instalar receptores tanto en victim como en todos los sitios usados como destino. El receptor incluido usa protocolo TCP interno, HTTP GET/POST y UDP; los eventos denominados SSH/DNS/mail son aproximaciones de carga, no clientes SSH/DNS/SMTP auténticos.

Peering mapea `peer-flow*` a un generador agregado. Puede ejecutar en el propio peer-router o en un host detrás de él; especificar IP/interfaz/gateway de datos. Si el generador corre en el router, su siguiente salto hacia victim debe reflejar su tabla real, no la IP del propio router. Las identidades `peer-flow*` son flujos lógicos, no cien IPs distintas. La categoría `other` conserva el tratamiento del generador original, no replay de MAWI.

## Instalación Linux

```bash
cd /opt/benign-lab
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.lock
pip install --no-deps --no-build-isolation -e .
```

En cada host ejecutor copiar `benign_lab/agent.py` a la ruta configurada. Requiere Python >=3.11; namespaces requieren iproute2 y permisos apropiados; ICMP requiere ping. Configurar claves SSH, known_hosts y sincronización NTP/chrony. El controlador usa huellas conocidas y autenticación no interactiva. Los agentes son Linux; el panel y la simulación se pueden ejecutar en Windows.

En victim y cada destino Enterprise:

```bash
python3 /opt/benign-lab/benign_lab/agent.py receiver --host IP_DE_DATOS --tcp-port 9001 --udp-port 9002 --http-port 8088
```

Sustituir `IP_DE_DATOS`; abrir esos puertos en el laboratorio. El servidor web de victim existente no implementa necesariamente el endpoint del receptor incluido.

```bash
benign-lab inspect-mapping --lab config/lab.yaml
benign-lab generate-plan --lab config/lab.yaml --seed 3 --duration 600 --out benign_plan.json
benign-lab inspect-mapping --lab config/lab.yaml --plan benign_plan.json
benign-lab serve --lab config/lab.yaml --data /var/lib/benign-lab --host 127.0.0.1 --port 8765
```

Acceder mediante un túnel SSH desde el navegador: `ssh -L 8765:127.0.0.1:8765 usuario@CONTROLADOR`. Para exponer directamente el panel, definir `BENIGN_API_TOKEN`, `BENIGN_ALLOWED_HOSTS` y usar TLS en un proxy. Un solo proceso del controlador; no múltiples workers.

Importar `benign_plan.json` en el panel, validar mapeo y ejecutar un piloto en modo Laboratorio (velocidad 1). Validar mapeo es comprobación estática. Al iniciar se comprueban asignación IP, ruta/interfaz/gateway y conectividad TCP/HTTP en cada agente antes de elegir el inicio común. UDP UL registra bytes enviados, no confirma recepción; ICMP y entrega UDP deben verificarse mediante capturas. La comprobación de ruta observa el siguiente salto, no certifica todo el recorrido ni el BNG/5GC/OVS.

Comparar capturas/contadores del datapath con IPs/puertos de `generated_events.csv`. Se conservan métricas de payload, no contadores L2 ni retransmisiones. Registrar el estado del BNG, DHCP y rutas antes del piloto; no modificarlo entre B0 y B0+attack. Un cambio de DHCP o ruta durante la corrida exige revisar resultados: las rutas se comprueban al preparar.

## Evidencia y pares reproducibles

Se conservan perfiles, derivación independiente de semillas, plan_hash y copia exacta del plan. Configuración, binding y evidencias están fuera del JSON del plan; `lab_hash` permite detectar diferencias. En modo real se rechazan capacidades de configuración distintas de las del plan.

El panel ofrece estado, logs, eventos, métricas TX/RX por dominio y evidencia de agentes. La exportación agrega `execution_mapping.json`: IPs/interfaces/rutas anunciadas por los agentes, sesión referenciada y contexto. SSE transmite observaciones; `metrics.jsonl` persiste métricas y dominios cada segundo. Ground truth mantiene ventanas de 5 s, warmup y etiquetas UNKNOWN para ataques previstos sin confirmar. B0+attack reutiliza el mismo archivo; los ataques se ejecutan externamente y se anotan en el panel.

Para detener, usar el panel. EOF/STOP cancela agentes; el controlador aplica un plazo de cierre. Un reinicio marca corridas incompletas como interrupted y no las reproduce automáticamente.

## Servicio opcional

`deploy/benign-lab.service` muestra un controlador systemd con rutas `/opt/benign-lab` y `/var/lib/benign-lab`. Crear un usuario de servicio y darle acceso a las claves/known_hosts; revisar rutas antes de instalarlo. No se instala automáticamente. Preferir ejecutar agentes remotos sin conceder privilegios de red al controlador.

## Estructura del proyecto

`planner.py` genera y valida planes; `profiles/` define BENIGN_V1; `config.py` resuelve contratos por dominio, adapters y agrupación; `agent.py` genera tráfico y comprueba IP/ruta; `runner.py` sincroniza, monitorea, detiene y persiste; `api.py` publica REST/SSE; `static/` contiene el panel; `ground_truth.py` produce ventanas de 5 s; `tests/` cubre planificación, API, tráfico y mapeo.
