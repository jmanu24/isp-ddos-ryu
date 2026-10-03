# Operación conectada — 1 de octubre de 2026

Esta guía describe el estado actual y reemplaza los pendientes de los informes
de inspección anteriores. BENIGN_V1, perfiles, semillas, planes reutilizables,
plan_hash SHA-256 y ground truth de 5 s permanecen conservados.

## Acceso y servicios

Panel: `http://192.168.18.154:8780`, con BENIGN_API_TOKEN. El token y las
credenciales SSH están en `.runtime/benign-lab/`, fuera de Git. La unidad
`benign-lab-web.service` escucha exclusivamente en la IP de gestión indicada;
BENIGN_ALLOWED_HOSTS incluye esa dirección y los hosts locales.

Aplicación: `/home/ubuntu/isp-ddos-ryu/deploy/vm-lab/tools/benign-lab`.
Configuración activa: `config/lab.connected.yaml`. El servicio corre como ubuntu.
Para un túnel alternativo:

```sh
ssh -N -L 8780:192.168.18.154:8780 ubuntu@192.168.18.154
```

Todas las conexiones a workers se originan en control. Las VMs Ubuntu usan
labadmin; victim Alpine conserva el acceso root existente. Las credenciales
se pasan por entorno a sshpass y no se incluyen en planes ni informes.
Agentes: `/opt/benign-lab/agent.py`. Receptores en los cinco sitios Enterprise
mediante systemd y en victim mediante OpenRC.

## Dominios conectados

- Mobile: cinco namespaces ue1…ue5, distribuidos entre ue y ue2.
- Fixed: diez namespaces fixed1–fixed10, cada uno con su macvlan, DHCP y ruta propios; las sesiones IPoE se verifican en accel-ppp/FreeRADIUS. Véase FIXED_NAMESPACES.md.
  El agente usa `--no-baseline` para mantener DHCP/rutas sin iniciar el anterior
  generador automático TCP_SYN. Las IPs actuales se reconciliaron al aplicar
  las capacidades; pueden cambiar tras nuevas renovaciones.
- Enterprise: cinco sitios accesibles; ent-site-2…5 se encendieron mediante govc.
- Peering: generador agregado por peer-router, tráfico a victim vía BR.

Victim tiene la ruta persistente `10.20.0.0/24 via 10.92.0.2 dev eth1`, también
incluida en Ansible. Peering tiene el reloj sincronizado y una ruta exclusiva
para NTP vía gestión; el tráfico del experimento conserva su ruta por BR.

## Capacidades experimentales aplicadas

| Dominio | Mediana UL Mbps | Mediana DL Mbps | Referencia Mbps |
|---|---:|---:|---:|
| Mobile | 4.44 | 16.36 | 4.44 |
| Fixed | 441.31 | 416.10 | 416.10 |
| Enterprise | 696.72 | 708.59 | 696.72 |
| Peering | 200.86 | 479.59 | 200.86 |

36 rondas con una única versión del medidor, dos conexiones por origen,
10 s por ronda y 2 s de calentamiento excluidos. Tres repeticiones por sentido,
ampliadas a cinco cuando la variación inicial fue grande. La referencia es el
menor de las medianas UL/DL. Se midió payload TCP efectivamente recibido.

`CAPACITY_CALIBRATION.md` contiene el procedimiento reproducible y
`CAPACITY_MEASUREMENTS.json` todos los datos, rutas, hash del medidor y errores.
Son referencias de rendimiento útil con estas VMs y generadores, no la
velocidad física ni una garantía de máximos simultáneos. Enterprise se midió
con reglas temporales del plano de datos limitadas al puerto de calibración.
Mobile registró un reinicio TCP en una conexión de bajada; sus bytes recibidos
y el periodo sin entrega forman parte de la medición. La subida no tuvo errores.

El controlador DDoS intervino en pruebas diagnósticas previas, por lo que se
excluyeron de la campaña final. Durante ésta se usó LAB_CALIBRATION_MODE con
telemetría/encaminamiento y sin detección/actuación, con restauración automática
y temporizador de respaldo. La detección normal quedó restaurada, las reglas
temporales se retiraron y la API muestra cero parámetros de mapeo pendientes.

## Versiones, validación y experimentos

Control: Python 3.8.10 con entorno propio y `requirements.lock`. Workers Ubuntu:
Python 3.10.12. Victim: Python 3.14.7. Se aprobaron 23 pruebas de la herramienta,
incluyendo el medidor en ambos sentidos, y una prueba del modo de calibración
del controlador. Su configuración predeterminada mantiene la detección activa.

El piloto de conectividad anterior está en `CONNECTED_PILOT.json`: 126 eventos,
149000 de 151200 bytes y seis transferencias cortas. Ese piloto no fue un
baseline científico. Tampoco la calibración ejecutó BENIGN_V1 de 600 s.

Para la campaña científica, materializar un nuevo plan con las capacidades
aplicadas y reutilizar exactamente su JSON en B0 y B0+ataque. Los planes
guardados conservan sus capacidades y hash originales. Comprobar antes de
cada campaña leases, sesiones, tasa entregada y falsos positivos del detector;
las capacidades aisladas no certifican el comportamiento conjunto.

```sh
cd /home/ubuntu/isp-ddos-ryu/deploy/vm-lab/tools/benign-lab
.venv/bin/benign-lab inspect-mapping --lab config/lab.connected.yaml
```

Datos, credenciales y respaldos están excluidos de Git. Las copias previas de
la configuración de calibración se conservan en `.codex-backups/benign-capacity`
y `.runtime/benign-lab/lab.before-calibration.yaml`. Los cambios del proyecto
se versionan en el repositorio del nodo control.


La versión optimizada incorpora supervisores por VM y perfiles de ejecución seleccionables. Ver [OPTIMIZED_EXECUTION.md](OPTIMIZED_EXECUTION.md). Los módulos agent.py, connection_pool.py y supervisor.py deben desplegarse juntos; los receptores Enterprise y Victim requieren reinicio para activar keep-alive.
