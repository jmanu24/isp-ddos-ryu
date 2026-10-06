# Validación del laboratorio — 6 de octubre de 2026

Se verificó el laboratorio desde el nodo control con el pipeline existente activo y sin pruebas de plataforma en ejecución. Se corrigió la adquisición de estadísticas. La conectividad de los destinos de las pruebas funciona, pero no hay conectividad completa entre dominios y se observó un falso positivo de mitigación.

| Comprobación | Resultado |
|---|---|
| Acceso a nodos configurados | 26/26 responden por SSH/local |
| VMs migradas en Workstation | 9/9 encendidas; sus originales ESXi permanecen apagados |
| Core y radio | Open5GS saludable, 2 CU y 5 DU con procesos activos; 5 servicios UE activos |
| Fixed | 10 sesiones IPoE activas; comprobados 10 namespaces con sus IP actuales |
| Enterprise y Peering | 5 receptores Enterprise activos, receptor victim activo, OVS conectado al controlador y BGP establecido |
| Destinos de tráfico | 21 clientes → victim y 20 pares dirigidos entre sedes Enterprise |
| ICMP/TCP/HTTP/UDP | 41/41 rutas pasaron cada protocolo: 164 comprobaciones positivas |
| Cruces entre dominios | 0/63 pings representativos; faltan rutas específicas de datos |
| Adquisición de tráfico | 26/26 colectores activos y 15 interfaces de namespaces visibles |
| Coherencia de tasas | 6.510 comparaciones: cero discrepancias con el intervalo real; cero retrocesos de contadores |
| Recursos | 2/2 hosts físicos y 26 series de invitados; también 16 series ESXi, no 42 VMs distintas |
| Auditoría de detección | Conectada y con registros recientes |

## Cambios aplicados

PE y victim ejecutan Alpine/BusyBox: `ip -j` no está disponible y el muestreador terminaba con CalledProcessError. Se añadió lectura IPv4 alternativa con `ip -o -f inet address show`; si no hay lectura válida se declara información desconocida, conservando los contadores. Se alineó el timestamp con la lectura de contadores y se agregó `counter_interval_s` para reconstruir las tasas exactamente. Se actualizaron las sondas en los nodos configurados y se refrescó únicamente benign-lab-web, sin una prueba activa. No se reiniciaron core, radio ni controlador ni se cambiaron umbrales, reglas, semillas o planes. Once tests focalizados pasaron.

Las transferencias confirmadas por el receptor fueron TCP 65.536 bytes de bajada, TCP 65.536 bytes de subida y HTTP 4.096 bytes de subida por representante de dominio. Los contadores directos de cada cliente y las muestras del dashboard registraron incrementos superiores al payload confirmado; son bytes de interfaz y contienen además encabezados/tráfico auxiliar. Se conservó el intento Enterprise inicialmente fallido y el reintento exitoso.

## Hallazgos pendientes

1. **Conectividad entre dominios:** Mobile, Fixed, Enterprise y Peering no tienen rutas explícitas entre sus redes de clientes. Los lookups observados en core, BNG, BR y sedes usan el gateway de gestión 10.10.0.254 para esos destinos. La matriz probó un representante por dominio desde cada cliente: 17 conexiones intra dominio respondieron y los 63 cruces interdominio fallaron. Las sedes Enterprise además tienen sus 20 rutas dirigidas comprobadas. No se cambió el aislamiento de la topología durante esta validación.
2. **Falso positivo:** la transferencia benigna de 10.70.0.11 a 10.55.0.100:9001 coincidió con una decisión SYN_FLOOD aceptada. Score efectivo 1,72455 frente al umbral 1,5; el backend reportó una orden de bloqueo por 60 s. La confirmación de transferencia falló entonces; la repetición aislada posterior pasó. Existe correlación temporal con evidencia de despacho, no una captura independiente de la regla histórica instalada. Revisar la clasificación y calibración antes de declarar correcto el comportamiento con mitigación activa; una observación no estima una tasa experimental de falsos positivos.
3. **Servicios auxiliares:** systemd-resolved aparece failed/start-limit-hit en suscriptor; logrotate figura failed en UE y UE2, aunque ambos pasaron validación de configuración en modo dry-run. También hay fallos fwupd-refresh en suscriptor, peer-router y cu2, y wait-online en UE2. No bloquearon los ensayos por IP. No se ejecutaron rotaciones ni se borraron logs para esta auditoría.
4. **Descartes de gestión:** aumentaron rx_dropped en control/ens160 y relay/eth0. No se atribuye esto a pérdida de aplicación en las rutas de datos: los ensayos de aplicación requeridos completaron sus cuotas salvo el evento correlacionado con mitigación descrito arriba.
5. **Gráfica PE:** br-ent es un puerto interno con contadores cero y estado down, mientras OVS y los puertos de datos reenvían correctamente. Para observar tránsito, seleccione eth1–eth5 en el selector de interfaces. No sumar RX+TX de todos los puertos como si fueran payload de extremo a extremo.

## Alcance y evidencia

Comprobaciones funcionales con tráfico pequeño, no benchmark de saturación ni garantía de estabilidad bajo máxima carga. Los fallos y huecos históricos de telemetría no se reconstruyeron. Todas las IP Fixed se descubrieron en sus namespaces; no se usaron las IP estáticas antiguas del archivo como evidencia del estado actual. Los 22 nodos con systemd informaron sincronización NTP; los dos gateways chrony informaron estado Normal y PE/victim tenían ntpd activo con desfases estimados dentro del presupuesto de 0,5 s, considerando incertidumbre de SSH.

La evidencia JSON y los diagnósticos originales están en `.runtime/benign-lab/health-validation` del control node. El informe JSON entregado incluye servicios, IP actuales, resultados, tasas, estados de los hosts, confirmaciones de payload y eventos de decisión/mitigación; no contiene credenciales.
