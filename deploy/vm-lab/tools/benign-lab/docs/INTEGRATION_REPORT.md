# Resumen técnico de integración

## Resultado

Proyecto original adaptado en sus módulos existentes; perfiles y planes BENIGN_V1 conservados. Los cuatro dominios tienen contratos de ejecución en `config.executor_for`, sobre los adaptadores locales, namespace, SSH y SSH+namespace. Se agregó inventario real incompleto, sin inventar IPs de gestión, más evidencia de IP/ruta y métricas por dominio en el panel.

| Dominio | Integración implementada | Verificación pendiente en las VMs |
|---|---|---|
| Mobile | Agente dentro de ue1…ue5, alias ue opcional; bind a IP UE y preflight de interfaz/ruta | Namespaces, IP UE, host SSH y recorrido DU/CU/5GC |
| Fixed | Sesión existente en namespace o IPoE por IP local; agentes separados por contexto/IP | IP/MAC/VLAN/interfaz de abonado, sesión activa accel-ppp/FreeRADIUS/DHCP, recorrido BNG |
| Enterprise | Ejecución en ent-site-1…5 y destinos intersite originales | IPs de gestión/datos, receptores y rutas PE/OVS/SDN |
| Peering | Un agente agregado para peer-flow*, IP origen, interfaz y gateway comprobado | Host generador, gateway de peer-router y camino BR/PE |

**Ninguna conexión con las 23 VMs fue establecida ni probada en esta entrega.** Se comprobó tráfico TCP/HTTP/UDP en loopback local. Los ejecutores SSH/netns quedaron implementados y configurables; su aceptación en el laboratorio requiere completar el inventario y ejecutar el piloto descrito en REAL_LAB_DEPLOYMENT.md.

## Cambios

- `config/lab.real.yaml`: UE, abonados, sitios, generador, destino conocido y parámetros pendientes explícitos.
- `config.py`: contratos por dominio, detección de parámetros pendientes, separación de agentes por binding y rechazo de capacidades distintas al plan.
- `agent.py`: binding de sockets TCP/HTTP/UDP e ICMP a IP origen; verificación de IP local, ruta/interfaz y gateway; evidencia transmitida antes del inicio común.
- `runner.py`: contextos enviados a agentes, evidencia exportada, IP/interfaz observadas por evento, métricas por dominio y restauración de logs al reiniciar.
- `api.py` y `static/`: inventario pendiente, contextos en validación de mapeo, métricas y evidencia de agentes en el monitor, dominios en metrics.jsonl.
- `cli.py`: inspect-mapping con listado de campos pendientes y código de salida 2 cuando falten valores.
- `docs/REAL_LAB_DEPLOYMENT.md`, `deploy/benign-lab.service`: despliegue, modos IPoE, receptores y piloto de aceptación.
- Tests de dominio, agrupación IP, rutas incorrectas, tráfico enlazado y API con inventario incompleto.

BENIGN_V1, ventanas de 5 s y semillas independientes no cambiaron. El ajuste de planner.py sólo mejora el error para capacidades pendientes (`null`). B0 y B0+attack consumen el mismo JSON; configuración y evidencia son artefactos separados. Los ataques siguen siendo externos, con anotaciones observadas para ground truth.

## Verificación realizada

Entorno Windows, Python 3.12, dependencias requirements.lock. Suite: **17 pruebas aprobadas, 2 omitidas por requerir agentes Linux/POSIX**. Las dos pruebas Linux del proyecto original no funcionan en Windows (pipes stdin y señales); se marcaron con skipif para ejecutarse normalmente en Linux. No se reemplazan por una afirmación de aceptación del laboratorio.

Se probaron TCP, HTTP y UDP con carga de 1200 bytes en ambas direcciones y binding a 127.0.0.1. Se comprobaron rechazos de ruta/interfaz/gateway mediante resultados iproute2 simulados. La API probó corridas B0/B0+attack con copias exactas del plan, exportación, parada, concurrencia y recuperación. Sintaxis Python y JavaScript verificada. Hay una advertencia de deprecación de Starlette/httpx en el cliente de pruebas.

Comparación contra el ZIP original: todos los YAML de perfiles son idénticos byte por byte. Planes completos de 600 s, capacidades 100 Mbps por dominio, semillas 1 y 3: JSON canónico idéntico antes/después.

| Semilla | plan_hash SHA-256 |
|---|---|
| 1 | 56768742fedb51db39a55b8f440ec8504190eb1be3eb845a2973a96aaef33994 |
| 3 | 96d7e7401820bb5c206506d9c3a7a7f3f7e02d92cf1f21330743a6a328121f38 |

## Límites y aceptación

No se aprovisionan DHCP/IPoE, BNG, RADIUS, UE, rutas ni namespaces. `session_id` es una referencia del operador, no validación de sesión mediante una API del BNG. Las rutas se comprueban al preparar, y sólo certifican la IP/interfaz y siguiente salto observado. Se requieren capturas y contadores externos para certificar el datapath completo, volumen L2 y entrega UDP UL.

Los nombres de aplicaciones describen aproximaciones de carga del generador original. SSH/DNS/mail no son implementaciones reales de esos protocolos; peering no reproduce PCAP MAWI. Las métricas son payload/chunks, no paquetes TCP observados. Una corrida completada no implica ajuste volumétrico perfecto: revisar bytes reales, desfases y errores del CSV.

Antes de campaña: completar host/user/clave, IP/interfaz/namespace, session_id/access_mode, gateway Peering, IPs de sitios y capacidades; desplegar agentes/receptores; ejecutar pytest en Linux; piloto por dominio con capturas; finalmente usar el mismo benign_plan.json y lab_hash para el par experimental.


## Actualización de ejecución optimizada (2 de octubre de 2026)

La plataforma conectada ya incorpora supervisores por VM, métricas agrupadas, persistencia en segundo plano y perfiles TCP/HTTP persistentes. La validación actual en Linux y el laboratorio real se documenta en [OPTIMIZATION_VALIDATION.md](OPTIMIZATION_VALIDATION.md); las instrucciones están en [OPTIMIZED_EXECUTION.md](OPTIMIZED_EXECUTION.md). Se conservaron BENIGN_V1 y el plan materializado original.

## Peering paralelo y comparación de baseline (3 de octubre de 2026)

La actualización incorpora dos procesos Peering deterministas y conserva las nueve sesiones SSH de generación. La política de CPU aplicada y su reversión están en [PEERING_PARALLEL_SCHEDULING.md](PEERING_PARALLEL_SCHEDULING.md). La validación más reciente (72 pruebas y tres baseline completos de 600 s) se documenta en [THREE_BASELINE_RESULTS.md](THREE_BASELINE_RESULTS.md). Los resultados anteriores se conservan como evidencia histórica.
