# 4.4.2 — Recurso protegido: configuración de la víctima y su calibración

Fecha: 2026-10-21. Repos: `isp-ddos-ryu` (rama `protected-resource-victim-syn`,
pusheada), `traffic-generator-pucp` (rama `pilot-diagnosis`, pusheada, con el
cambio al generador de ataque y los scripts de calibración de este prompt —
ver §8). No se tocó ninguna lógica de detección, decisión ni mitigación del
controlador.

**Resultado: el criterio de paso se cumplió**, con el recurso protegido (§3)
y, tras tu confirmación, un cambio real en `benign_lab.agent.attack_flood()`
(§6) — el generador de ataque `syn_flood` nunca ocupaba la cola de
aceptación de la víctima, con ninguna configuración de sysctl, porque
auto-abortaba cada conexión con un RST casi inmediato. Corregido y validado
con números en vivo: **A(C2, composición 3) = 7,7%** contra **A(C1) =
84,6%** (necesitaba ≤64,6%), y el ataque de un solo dominio no degrada nada
(84,6% = A(C1)), confirmando que solo M tiene algo que proteger en la
composición confirmatoria. Detalle completo en §4-§7.

## 1. Inventario (solo lectura, 10.55.0.100 / 10.10.0.100, host `victim`)

Alpine Linux 3.24.1, kernel `6.18.50-0-virt`, OpenRC, 4 vCPU, 971 MB RAM.

| parámetro | valor original |
|---|---|
| `net.ipv4.tcp_syncookies` | 1 |
| `net.ipv4.tcp_max_syn_backlog` | 128 |
| `net.core.somaxconn` | 4096 |
| `net.ipv4.tcp_synack_retries` | 5 (~63 s de permanencia de un half-open) |
| `net.ipv4.tcp_abort_on_overflow` | 0 |

Servicios: `victim-http` (puerto 80, stdlib `http.server`, no es objetivo de
ningún plan) y `benign-lab-receiver` (`agent.py receiver --workers 4`, 4
procesos `SO_REUSEPORT`, cada uno con backlog `asyncio` por defecto = 100,
escuchando TCP 9001/8088 y UDP 9002 — el receptor real que comparten tráfico
benigno y ataque).

Contadores acumulados (18 días, antes de cualquier cambio): `SyncookiesSent`=
305655, `ListenOverflows`=0, `ListenDrops`=1555, `TCPReqQFullDrop`=0 — ya
entonces la cola de aceptación nunca había sido el cuello de botella en
ningún ataque corrido contra esta víctima (causa, no solo síntoma — ver §5).

Piso de concurrencia benigna medido (plan real, semilla 201): hasta 79
conexiones TCP simultáneas a `victim-web`, hasta 64 nuevas en el mismo
segundo. Composición 3 (`data/attack_plans/composition3_multidomain_under_threshold.json`):
`syn_flood`, Σ=161,322 pps (2,10×`SYN_THRESHOLD`=76,82), por dominio
enterprise 69,138 pps (f=0,9), fixed 53,774 pps (f=0,7), mobile 38,41 pps
(f=0,5), cada uno bajo su propio umbral por diseño. Carga en bits: 82,6 kbps
en total.

## 2. Alternativas consideradas

**A — SYN (elegida)**: `tcp_syncookies=0` (para que la cola de aceptación
vuelva a ser el recurso finito que hoy la protege) + `tcp_synack_retries=2`
(acorta la permanencia de un half-open de ~63 s a ~3 s, para que la tasa de
huecos liberados por segundo sea comparable a las tasas de ataque y la
degradación sea graduada, no binaria). `tcp_max_syn_backlog` se dejó en 128
(sin cambio) porque el piso de concurrencia benigna medido (79/64) está
cerca de ese límite.

**B — Capacidad (`tc`)**: descartada — composición 3 pesa 82,6 kbps, 3-4
órdenes de magnitud por debajo de cualquier capacidad de referencia del
laboratorio (enterprise 696,72 Mbps, fixed 416,1 Mbps); limitar el enlace lo
suficiente para que importe degradaría también C1.

## 3. Cambio aplicado en la víctima, y reversión

Rol Ansible versionado (`isp-ddos-ryu`, rama `protected-resource-victim-syn`,
commit `85b5acc`, pusheado): `deploy/vm-lab/ansible/roles/victim/tasks/
syn_protection.yml`, con el toggle `victim_vulnerable_syn_enabled` (default
`false` → valores originales 1/5). Playbook standalone
`playbooks/toggle_victim_syn_protection.yml` aplica o revierte sin tocar el
resto del rol `victim`.

Validado con `--check --diff` antes de aplicar de verdad. Estado en vivo tras
aplicar: `tcp_syncookies=0`, `tcp_synack_retries=2`, `tcp_max_syn_backlog=128`
(sin cambio). Archivo desplegado `/etc/sysctl.d/90-victim-syn-protection.conf`,
sha256 `2e1195dfd069f49212509b847dc5ad3667dc8ba7c78ee1a2017bd9d3796eabc5`
(coincide con el commit).

**Reversión**: `ansible-playbook playbooks/toggle_victim_syn_protection.yml`
sin `-e` (el default `false` restaura `syncookies=1`/`synack_retries=5`).

## 4. Primer intento de calibración — no cumplió, causa confirmada en vivo

3 corridas reales (semilla 201, pipeline suspendido) con **solo** el cambio
de §3 ya aplicado mostraron que el criterio no se cumplía: A(C2, composición
3) = 92,3%, A(C1) = 76,9% en la misma ventana — composición 3 **no degradaba
nada** frente al propio ruido de C1, y el ataque de un solo dominio dio
exactamente el mismo A que C1 (76,9% los dos).

**Causa, confirmada en vivo, no una hipótesis**: los contadores TCP de la
víctima no se movieron ni un evento entre el inventario original (§1) y
después de esas 3 corridas (`SyncookiesSent`, `ListenOverflows`,
`ListenDrops`, `TCPReqQFullDrop` — los 4 idénticos). La cola de aceptación
**nunca fue tocada** por el ataque, con o sin syncookies. Revisando
`benign_lab/agent.py` (`attack_flood()`, rama `syn_flood`, versión
original): cada "SYN" era un `socket.connect()` no bloqueante seguido, en el
mismo `finally`, de `sock.close()` con `SO_LINGER(1,0)` — eso fuerza un RST
hacia la víctima casi inmediatamente después del SYN, en vez de dejar la
conexión a medio abrir. Un RST en estado `SYN_RECV` libera el `request_sock`
del kernel al instante, mucho antes de que `tcp_synack_retries` tenga
oportunidad de importar: el generador no producía un flood de medio-abiertas
real, con ninguna configuración de la víctima — explica también por qué los
contadores nunca se habían movido en 18 días de corridas previas (§1).

Esto llevó al punto de decisión del §6 (ver abajo): el cambio de víctima por
sí solo no basta; corregir el generador de ataque (`traffic-generator-pucp`,
no el controlador) es lo que falta.

## 5. Investigación del mecanismo real (sin spoofing, sin hping3/scapy… hasta que hubo que usarlos)

Pediste explícitamente usar `hping3` o `mhddos`. Evalué ambas: `mhddos` es
una herramienta externa pesada orientada a ataques reales no autorizados,
innecesaria aquí; `hping3` ya está instalado en este laboratorio
(enterprise_site, peer_router, y ya se usa en el propio playbook de mobile),
así que la usé — con una salvedad importante que también hubo que resolver.

**Por qué un socket normal nunca basta, sin spoofing**: un SYN real desde un
host alcanzable completa el handshake automáticamente en el kernel del
propio atacante en cuanto llega el SYN-ACK — o, si se cierra antes, el
kernel manda un RST — independientemente de lo que haga el código Python.
`hping3 --syn` manda un SYN crudo sin ese estado de socket, pero por eso
mismo tiene el MISMO problema en sentido inverso: el kernel del atacante,
al recibir un SYN-ACK que no reconoce, también lo responde con un RST
automático. **Confirmado en vivo con una regla `nft` acotada por rango de
puerto** (que descarta ese SYN-ACK entrante antes de que el kernel lo vea,
sin tocar el tráfico benigno que comparte el mismo host/puerto): con la
regla puesta, `TCPReqQFullDrop` de la víctima subió de 0 a 742 en segundos.
Validado en los 3 dominios que usa composición 3 (enterprise, fixed/macvlan,
mobile/NOARP) — ninguno tenía en realidad el problema de ARP/PPP que una
nota antigua del repo atribuía a `fixed` (esa nota era de la época PPPoE, ya
abandonada).

**Pero el mecanismo real resultó más sutil, con 3 bugs encadenados,
cada uno confirmado por separado antes de corregirlo:**

1. **hping3 necesita una terminal controladora para `-i`/`-c`.** Sin ella
   (pipes/`DEVNULL`, probado tanto con `asyncio.create_subprocess_exec` como
   con `subprocess.Popen` clásico en un hilo), este build de hping3
   (3.0.0-alpha-2, de 2004) termina tras una fracción de `-c` con código de
   salida limpio y estadísticas contradictorias (`"transmitted"` mucho menor
   que `"received"`, pérdida de paquetes negativa). Con un pty asignado vía
   `pty.openpty()` se comporta como una corrida interactiva real. Confirmado
   aislado (sin tráfico benigno concurrente): sin pty, 2074 paquetes
   pedidos, el proceso termina en <1 s; con pty, corre los ~60 s completos.
2. **Con tráfico benigno concurrente, `-c` sigue siendo el problema — por
   otra razón.** En una corrida real (B0+attack), el `tail` capturado del
   pty mostraba paquetes de **datos reales** (`len=1252`, `flags=AP`) del
   tráfico benigno que comparte el mismo host y puerto 9001 — hping3 los
   cuenta como "recibidos" sin filtrar por puerto de destino exacto, así que
   el tráfico benigno ambiente por sí solo hace que su contador de
   recepción llegue a `-c` casi de inmediato, terminando el flood tras una
   fracción de su duración real. **Corrección**: no pasar `-c` en absoluto
   — dejar que hping3 corra indefinidamente al ritmo de `-i`, y que el
   propio `asyncio.wait_for(..., timeout=...)` + `kill()` de este código
   controle la duración real, sin depender de cuánto (mal)cuenta hping3.
3. **La limpieza (drenar el pty + borrar la regla `nft`) competía con una
   cancelación externa justo en el `deadline` del evento.** Esperar hasta
   `deadline` (o unos segundos después) para recién empezar a matar el
   proceso perdía la carrera contra esa cancelación externa en los dominios
   más lentos (`fixed`/`mobile`, que pasan por `ip netns exec`) — la
   corrida completaba el envío correctamente, pero las métricas finales
   nunca se escribían (`attack_pps_actual=null`, `"Deadline reached"`).
   **Corrección**: matar `hping3` 1,0 s **antes** del `deadline` real
   (`SYN_FLOOD_CLEANUP_LEAD_S`), dejando margen para que la limpieza
   termine dentro de la ventana que el supervisor externo permite.

Cada uno de los 3 se encontró, se confirmó por separado contra el laboratorio
real (no en abstracto) y se corrigió antes de pasar al siguiente — el commit
final en `traffic-generator-pucp` (`benign_lab/agent.py`, rama
`pilot-diagnosis`) documenta los 3 en los comentarios del propio código.

**Validación final, por dominio, de las 6 fuentes que usa composición 3**
(verificaciones aisladas antes de la calibración completa): las 6 corrieron
limpias (`error=None`), con `attack_pps_actual` dentro de ~2% de
`attack_pps_target` en cada una, y el agotamiento real de la cola confirmado
en vivo (`TCPReqQFullDrop` subió +37 200 en una corrida aislada de
composición 3 completa).

## 6. Decisión que pediste y ejecutaste

Dado el hallazgo del §4, propuse 3 opciones (modificar `attack_flood()`,
cambiar el vector, o documentar la limitación sin corregir). **Elegiste
modificar `attack_flood()`**, con la razón explícita de que cambiar el
vector rompería la capacidad del orquestador de detectar/mitigar SYN floods
— razón válida en sí misma, aunque la detección (basada en pps observados
por telemetría) nunca dependió de este mecanismo: lo que estaba en juego acá
era solo si el ataque *degrada el servicio* de forma medible, no si el
detector lo ve.

**Cambio aplicado** (`traffic-generator-pucp`, `benign_lab/agent.py`, rama
`pilot-diagnosis`, sin commitear — ver §8): la rama `syn_flood` de
`attack_flood()` ahora lanza `hping3 --syn` con un pty, sin `-c`, bajo una
regla `nft` temporal y acotada por puerto (instalada antes de cada ráfaga,
retirada siempre al terminar, incluso si `hping3` falla). No se tocó
`udp_flood` ni `icmp_flood`. Desplegado a los 10 nodos atacantes/receptor vía
`scripts/install_execution_agents.py` (verificado: ningún experimento activo
antes de cada despliegue; hash del archivo desplegado confirmado idéntico al
commit local en cada paso — sha256 final
`be47f402e96ffe4259df129aa28cfbf3f789d0124d868e7d01a9a7f6d66220f2`).

3 pruebas unitarias nuevas en `tests/test_attack_generation.py` (mockeando
`asyncio.create_subprocess_exec`, sin depender de `hping3`/`nft` reales):
lanza `nft`+`hping3`+limpieza en orden correcto, limpia la regla `nft` aunque
`hping3` falle al inicio, y trata el *kill* por `deadline` como éxito, no
como error. 12/12 pasan; resto de la suite sin regresiones nuevas
atribuibles a este cambio (10 fallos preexistentes, confirmados
reproducibles sin mis cambios vía `git stash`, en su mayoría por falta de
`fastapi` en este entorno).

## 7. Calibración final (semilla 201, pipeline suspendido, sin tocar detección)

3 corridas reales, con el dominio móvil restablecido primero (requerido
porque `restore_mobile_budgets` exige las 5 UE con sesión e indicación KPM
fresca incluso con `pipeline=baseline`):

| condición | run_id | plan ataque | estado |
|---|---|---|---|
| C1 (sin ataque) | `20261021T211850-3491b2c7` | — | `completed_with_errors` |
| C2 + composición 3 | `20261021T212732-c91a8ebb` | `1990310a26c6…` (Σ=161,3 pps, 6 fuentes) | `completed_with_errors` |
| C2 + un solo dominio | `20261021T213244-f2f52a2e` | `89e927a86946…` (enterprise, f=0,9, 69,1 pps, 2 fuentes — mismas fuentes/tasa/tiempos que el componente enterprise de composición 3) | `completed_with_errors` |

(`completed_with_errors` es el estado habitual de estas corridas — coincide
con fallos individuales de eventos benignos ya documentados en
`PILOT_DIAGNOSIS.md`, no con un fallo de la corrida ni del ataque; las 3
corrieron los 180 s completos. Los 8 eventos de ataque de las 2 corridas con
ataque completaron limpios, `error=None`, `attack_pps_actual` dentro de
~2% del objetivo.)

### 7.1 Resultados numéricos

Entrega% (bytes entregados/planificados) y A% (D=90%, L=150ms, ventanas de
5 s), calculados con `response_metrics.py` sobre los registros LAB_AUDIT
crudos de cada corrida:

| condición | entrega% run completo | A% [0,60) | A% [60,120] (ventana) | A% (120,180] |
|---|---|---|---|---|
| C1 | 97,2 | 100,0 | **84,6** | 83,3 |
| C2 + composición 3 | 88,3 | 100,0 | **7,7** | 91,7 |
| C2 + un solo dominio | 95,6 | 83,3 | **84,6** | 83,3 |

Entrega% por dominio en la ventana de ataque [60,120]:

| condición | enterprise | fixed | mobile | peering |
|---|---|---|---|---|
| C1 | 99,95 | 92,88 | 98,84 | 98,99 |
| C2 + composición 3 | 99,59 | **44,74** | 99,32 | **69,35** |
| C2 + un solo dominio | 99,97 | 85,61 | 98,95 | 93,42 |

Contadores reales de la víctima (cumulativos; confirman agotamiento real,
no solo el indicador A): en la verificación aislada de composición 3
completa, `TCPReqQFullDrop` pasó de 8 658 a 45 858 (**+37 200**) en una sola
corrida de 60 s de ataque.

### 7.2 Criterio de paso

**A(C2, composición 3) ≤ A(C1) − 20 pp** → necesitaba ≤ 64,6 % (84,6−20).
**Medido: 7,7 %. Cumplido, con margen amplio** (76,9 pp por debajo del
límite, no al borde). El ataque de un solo dominio dio **84,6 %**,
**idéntico** a A(C1) (84,6 %) — degradación nula, confirmando que, en la
composición confirmatoria, **solo M (correlación cruzada de dominio) tiene
algo real que proteger**: ningún dominio por separado agota la cola, pero la
suma de los 6 sí.

**C1 no se degradó** respecto de la línea base anterior
(`PILOT_DIAGNOSIS.md` §2: A = 80,1 % pre-ataque / 86,6 % post-ataque con la
configuración **original** de la víctima): A(C1) aquí = 84,6 % en la misma
ventana, 83,3 % pre/post — del mismo orden, sin degradación atribuible al
cambio de sysctl ni al cambio del generador.

**fixed y peering cargan casi todo el impacto** (fixed 92,9→44,7 %, peering
99,0→69,3 %); enterprise y mobile casi no se mueven (99,95→99,59,
98,84→99,32) — consistente con que el `tcp_max_syn_backlog`=128 compartido
por todo el host se satura más rápido cuando también compiten con la propia
sobrecarga de recibir el ataque, y con que fixed/peering tienen menos margen
de capacidad de referencia que enterprise.

## 8. Trazabilidad

| archivo | dónde | estado |
|---|---|---|
| `roles/victim/tasks/syn_protection.yml`, `defaults/main.yml`, `playbooks/toggle_victim_syn_protection.yml`, `ansible.cfg` | `isp-ddos-ryu` | commiteado (`85b5acc`) y pusheado a `protected-resource-victim-syn` |
| `/etc/sysctl.d/90-victim-syn-protection.conf` (víctima) | 10.10.0.100 | desplegado, sha256 `2e1195df…9e0`, coincide con el repo |
| `benign_lab/agent.py` (`attack_flood()`, rama `syn_flood`) | `traffic-generator-pucp`, rama `pilot-diagnosis` | commiteado (`5c7d33a`) y pusheado; desplegado en vivo a los 10 nodos, sha256 `be47f402e96ffe4259df129aa28cfbf3f789d0124d868e7d01a9a7f6d66220f2`, coincide con el commit |
| `tests/test_attack_generation.py` (3 pruebas nuevas) | `traffic-generator-pucp` | commiteado (`5c7d33a`) y pusheado |
| `scripts/generate_protected_resource_calibration_plan.py`, `register_protected_resource_plans.py`, `run_protected_resource_calibration.py` | `traffic-generator-pucp` | commiteado (`5c7d33a`) y pusheado |
| `data/attack_plans/composition3_enterprise_only.json` + entrada en `attack_plans_manifest.json` | `traffic-generator-pucp` | generado, hash `89e927a8694615757e970be978f9ef24832afc701c3aa9c6406e0dab8a79456d`, registrado en el servidor del panel — `data/` está gitignorado en este repo, no se commitea |
| `.runtime/benign-lab/calibration/protected_resource_calibration_manifest.json` | `isp-ddos-ryu` (datos) | run_ids + estados de las 3 corridas finales |

Repositorio y despliegue sin divergencias: el hash desplegado en los 10
nodos coincide exactamente con el del commit `5c7d33a`.

## 9. Supuestos y límites

- A usa los valores por defecto *provisionales* de `response_metrics.DEFAULTS`
  (D=90%, L=150ms, ventanas de 5 s), no confirmados independientemente,
  mismo estado que en `PILOT_DIAGNOSIS.md`.
- La comparación de C1 con "la línea base anterior" usa los números de
  `PILOT_DIAGNOSIS.md` §2 (C2 pre/post-ataque, misma configuración de
  víctima que antes de este prompt) como la referencia más cercana
  disponible — no existe una corrida C0 histórica idéntica (benigno,
  pipeline suspendido, semilla 201, sin ataque) previa a estos cambios.
- Las 3 corridas finales quedaron en `completed_with_errors` (no
  `completed`) — revisado: coincide con el patrón de fallos de eventos
  benignos individuales ya caracterizado en `PILOT_DIAGNOSIS.md`, no con un
  problema de esta calibración ni del cambio al generador.
- El rango de puertos reservado para `hping3` (`SYN_FLOOD_SPORT_BASE=20000`)
  se eligió por debajo de `ip_local_port_range` (32768-60999, confirmado en
  los nodos atacantes) para no solapar con los puertos efímeros del tráfico
  benigno del mismo host — no se probó el límite superior de cuántas fuentes
  concurrentes podría sostener sin ajustar ese rango.
- `SYN_FLOOD_CLEANUP_LEAD_S=1,0 s` es un valor elegido empíricamente (bastó
  para que `fixed`/`mobile`, los dominios más lentos por pasar por `ip netns
  exec`, terminaran su limpieza a tiempo en estas corridas) — no se validó
  un margen de seguridad formal para hosts aún más lentos.
