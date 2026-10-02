# Fixed: aislamiento por suscriptor

La VM `suscriptor` conserva sus dos interfaces físicas. Cada cliente tiene un namespace `fixed1`…`fixed10`, con su macvlan `macvlan1`…`macvlan10`, MAC original `02:00:00:00:00:01`…`0a`, DHCP independiente y tabla de rutas propia. El gateway sigue siendo `10.20.0.1`. Las IP se obtienen de DHCP; no son identificadores permanentes.

El agente de sesiones se ejecuta en el host para conservar el FIFO y la API de control. Sus clientes DHCP y generadores se ejecutan dentro del namespace correspondiente cuando `BNG_SUBSCRIBER_NAMESPACES=1`. Las acciones de renovar sesión y los futuros generadores controlados por el agente también utilizan ese namespace. Se conserva `--no-baseline` para evitar tráfico automático.

Persistencia: `bng-macvlans.service` crea namespaces e interfaces antes de `bng-subscriber-agent.service`. La plantilla Ansible del servicio configura la variable de aislamiento; `simulation/bng_subscriber_agent.py` implementa DHCP y ejecución en namespaces. No se necesita crear VMs adicionales. Los namespaces comparten CPU, memoria y kernel del host.

En la herramienta, los diez nodos Fixed usan `adapter: ssh_netns`, `namespace: fixedN`, `sudo: true`, `access_mode: ipoe_namespace` y su `interface: macvlanN`. El modo baseline lee las IP dentro de cada namespace y actualiza el mapeo de IP/sesión antes de iniciar los trabajadores. No cambia BENIGN_V1, las semillas, los planes existentes ni el ground truth de 5 s.

Las gráficas de tráfico recogen los contadores dentro de los diez namespaces. El host aparece aparte; sus interfaces de gestión no se mezclan con las de un suscriptor.

Verificación en la VM: `sudo ip netns list`; `sudo ip -n fixed1 -4 addr`; `sudo ip -n fixed1 route`; `sudo ip netns exec fixed1 ping -c 2 10.20.0.1`. La tabla del BNG se consulta en bng con `sudo accel-cmd -p 2000 show sessions`; comprobar MAC, IP y estado activo, no asumir que ipoeN coincide con fixedN.

Se conserva una copia previa en `/opt/bng-subscribers/backup-before-namespaces-20261002T035559` de la VM suscriptor. Para recuperar la arquitectura anterior durante mantenimiento: detener los generadores y el agente; liberar DHCP dentro de cada namespace; mover cada macvlan al namespace del host antes de eliminar su namespace; restaurar agente, script y unidad desde la copia; recargar systemd y arrancar los servicios; restaurar los ejecutores del dashboard a ipoe_bound y reconciliar DHCP/BNG. No eliminar namespaces que aún contienen las interfaces.

Antes de migrar se observaron diez IP locales pero solo nueve sesiones del BNG. El aislamiento no impide que el pipeline normal termine una sesión por mitigación. Las pruebas de baseline deben verificar la recuperación y registrar la restauración del pipeline.
