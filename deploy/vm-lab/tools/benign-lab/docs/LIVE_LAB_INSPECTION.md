# Inspección real de isp-ddos-ryu — 1 de octubre de 2026

Acceso SSH validado a `ubuntu@192.168.18.154`. Proyecto confirmado: `/home/ubuntu/isp-ddos-ryu`, revisión `aa7ae879332364bd0bfd2b0f9aa19617dbe6d52f`, sin cambios Git observados. Esta inspección reemplaza la afirmación de ausencia de acceso remoto del informe original; no implica que los agentes BENIGN Lab estén desplegados.

Se usó la topología `deploy/vm-lab/topology.yaml` y el acceso existente del proyecto para consultar las VMs. No se reiniciaron servicios, cambiaron rutas ni ejecutaron experimentos. `config/lab.discovered.yaml` contiene el inventario observado; todas las entradas permanecen `configured: false` hasta verificar despliegue y autenticación de los agentes. No contiene contraseñas ni claves privadas.

## Mobile

| Origen lógico / namespace | Host SSH (labadmin) | IP UE | Interfaz |
|---|---|---|---|
| ue1 | 10.10.0.8 | 10.45.1.2 | tun_srsue |
| ue2 | 10.10.0.8 | 10.45.1.4 | tun_srsue |
| ue3 | 10.10.0.8 | 10.45.1.5 | tun_srsue |
| ue4 | 10.10.0.16 | 10.45.1.6 | tun_srsue |
| ue5 | 10.10.0.16 | 10.45.1.7 | tun_srsue |

Cada namespace activo tiene ruta hacia `10.55.0.100` por tun_srsue. Ambos hosts contienen nombres ue1…ue5; los namespaces sin TUN/IP no son ejecutores activos. El CSV `config/ue_ip_map.csv` del repositorio usa otras redes (10.60.*), por lo que no se tomó como fuente de IPs actuales.

## Fixed

Host `suscriptor`: `labadmin@10.10.0.9`. Ocho macvlans sobre ens192. El enrutamiento por IP origen hacia victim selecciona gateway `10.20.0.1` e interfaz macvlan correspondiente, en tablas 101…108.

| Abonado lógico propuesto | Interfaz | IP DHCP observada | Sesión BNG observada |
|---|---|---|---|
| fixed1 | macvlan1 | 10.20.0.19 | ipoe0 active |
| fixed2 | macvlan2 | 10.20.0.20 | ipoe1 active |
| fixed3 | macvlan3 | 10.20.0.12 | No apareció en show sessions |
| fixed4 | macvlan4 | 10.20.0.13 | ipoe3 active |
| fixed5 | macvlan5 | 10.20.0.14 | ipoe4 active |
| fixed6 | macvlan6 | 10.20.0.15 | ipoe5 active |
| fixed7 | macvlan7 | 10.20.0.16 | ipoe6 active |
| fixed8 | macvlan8 | 10.20.0.17 | ipoe7 active |
| fixed9–10 | Ausentes | Pendiente | Pendiente |

BNG `10.10.0.2`: `accel-pppd.service` y FreeRADIUS activos; CLI en puerto 2000, no el puerto por defecto 2001. Consulta válida: `sudo -n accel-cmd -p 2000 show sessions`. Se observaron siete sesiones activas. El plan BENIGN_V1 conserva diez abonados; no se colapsaron las identidades ni se alteró la población. Para ejecutar el perfil completo hacen falta las dos interfaces/sesiones restantes y validar fixed3; las IPs DHCP pueden cambiar y deben reconfirmarse antes de la campaña.

## Enterprise

`ent-site-1`: SSH `labadmin@10.10.0.21`, datos `10.70.0.11` sobre ens160, gestión ens192. Rutas directas por ens160 hacia victim y `10.70.0.12`. La topología declara ent-site-2…5 con gestión `10.10.0.22…25` y datos `10.70.0.12…15`, pero los cuatro accesos SSH devolvieron No route to host. No se certificaron sus interfaces ni servicios.

El tráfico intersite en la misma subred puede circular por el vSwitch del segmento ENT_LAN sin atravesar pe; debe verificarse con capturas si se requiere observarlo en Ryu. El diseño hacia victim usa un segmento distinto del bridge pe.

## Peering y victim

`peer-router`: `labadmin@10.30.0.2`, IP de datos 10.30.0.2 sobre ens160. Ruta a victim vía 10.30.0.1 (BR), instalada por BIRD. El wrapper del proyecto resolvía este nodo sin IP de gestión (None); la inspección usó explícitamente la IP PEERING declarada. No se modificó el wrapper remoto.

Victim: SSH `root@10.10.0.100`, datos `10.55.0.100` sobre eth1; gestión eth0. Python 3.14.7. Alpine usa ip de BusyBox, por lo que `ip -br` no está disponible. No se encontró iperf3 y los receptores BENIGN Lab no se desplegaron.

## Compatibilidad y condiciones pendientes

El nodo de control tiene Python 3.8.10; UE, suscriptor, BNG, core5g, ent-site-1 y peer-router anuncian Python 3.10.12. BENIGN Lab requiere >=3.11 por asyncio.timeout/timeout_at. Es necesario proveer un intérprete compatible o adaptar y probar compatibilidad antes del despliegue; no basta completar las IPs.

Las capacidades por dominio no se deducen de la velocidad de las vNICs; siguen pendientes de calibración. La nueva clave de Codex sólo se autorizó en el nodo de control, no en las VMs. El acceso interno observado usa las credenciales existentes del proyecto; el ejecutor de BENIGN Lab requiere autenticación no interactiva por clave y known_hosts verificados.

No se probaron entrega de payload, puertos de receptores, capturas del recorrido completo ni métricas de la herramienta en las VMs. La validación realizada confirma acceso de gestión, asignaciones y decisiones de ruta. Evidencias: `lab-inspection.jsonl` y `lab-fixed-validation.jsonl`.
