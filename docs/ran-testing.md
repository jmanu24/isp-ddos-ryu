# RAN stack: srsRAN Project replacement, UE connectivity, and E2SM-KPM telemetry

Estado: **1 UE real confirmado de punta a punta (RACH → RRC → PDU Session → internet real vía
el UPF → tráfico real hasta `victim` → KPM por UE atribuido correctamente en el RIC).**
Multi-UE (broker GNU-Radio): **confirmado que SÍ puede aislar 3 UEs reales** (7 PRACH distintos
+ 1 attach completo en una corrida) tras arreglar dos causas raíz reales (preamble hardcodeado
en srsRAN_4G, `ue` con vCPUs insuficientes) — pero sigue siendo no-determinístico, peor que el
~50% de flakiness de RACH ya conocido para 1 solo UE. Fecha: 2026-09-20.

Automatización: `deploy/vm-lab/ansible/playbooks/test_single_ue.yml`,
`test_three_ue_broker.yml`, `test_kpm_validation.yml` — ver §5.

## 1. Reemplazo de OCUDU por srsRAN Project

El `ran_srsran` role usaba OCUDU (el propio fork/sucesor de srsRAN Project) como gNB. Tras una
sesión larga de debugging persiguiendo un fallo de RACH no resuelto sobre OCUDU (ver el
historial de commits de `ran_srsran` para el detalle completo — bugs de executor-stall,
reconexión ZMQ, y un bug de logger que resultó estar mal diagnosticado), se decidió volver al
proyecto original. No es una afirmación de que OCUDU tuviera la culpa — el propio README de
srsRAN Project (commit `4bf1543`, de su mantenedor oficial) ya apunta a OCUDU como su sucesor —
pero srsRAN Project es el más probado/usado de los dos, y valía la pena reintentar ahí.

**Cambios:**
- `/opt/ocudu` eliminado por completo de la VM `ran` (1.8GB).
- `ran_srsran/tasks/main.yml` clona `github.com/srsRAN/srsRAN_Project`, pinneado a
  `release_25_10` (el tag más reciente al momento, vía `git ls-remote --tags` — no floating en
  `main`, mismo criterio que `srsRAN_4G`/OCUDU ya seguían).
- 3 de los 4 patches de OCUDU se **portaron** (no copiaron a ciegas) al código real de
  srsRAN Project, confirmando primero que el mismo patrón de bug existe ahí:
  - `srsran-rlc-am-executor-stall-workaround.patch` y
    `srsran-f1ap-du-executor-stall-workaround.patch` — aplicaron con el mismo patrón
    (`execute_and_continue_on_blocking()`/`defer_and_continue_on_blocking()` suspendido para
    siempre bajo virtualización), confirmado presente verbatim vía grep antes de aplicar.
  - `srsran-zmq-reconnect.patch` — reescrito desde cero: srsRAN Project **no tenía ningún**
    mecanismo de recuperación para un REQ/REP ZMQ desincronizado (confirmado: no existe
    `reconnect()`/`rebind()` en el código original), a diferencia de OCUDU que ya lo tenía
    parcheado. Incluye también el throttle de EAGAIN (backoff de 500µs) de la misma sesión de
    debugging.
  - El workaround de MAC/RLC-TM (`ocudu-571-executor-stall-workaround.patch` original) **no se
    portó** — el mismo patrón de código existe en `mac_cell_processor.cpp`, pero el gNB arrancó
    limpio sin necesitarlo. Si el gNB se cuelga al activar la celda, ese es el primer lugar a
    revisar.

## 2. UE único, cross-VM: confirmado de punta a punta

Setup real usado (no colocado — gNB en `ran`, UE en `ue`, dos VMs separadas, tráfico ZMQ real
sobre la red RAN):

```
ran:  gnb -c /etc/srsran/gnb_zmq.yaml
ue:   srsue /etc/srsran/ue_direct_zmq.conf
```

Resultado confirmado en corridas reales: RACH → `RRC Connected` → `PDU Session Establishment
successful, IP: 10.45.1.2` → `RRC NR reconfiguration successful` → operación estable continua
(PUCCH/BSR cicleando, sin errores en 4 líneas de log en toda la corrida).

**No-determinismo conocido, sin arreglo de aplicación encontrado:** el RACH falla ocasionalmente
en el primer intento (7/7 preambles transmitidos, nunca respondidos por el gNB). Reintentar
(matar y relanzar el UE, a veces también el gNB) resuelve en 1-3 intentos, siempre. El playbook
`test_single_ue.yml` no reintenta automáticamente — si falla, simplemente volvé a correrlo.

**Paso manual que SÍ hace falta siempre** (no se puede provisionar de antemano — la interfaz no
existe hasta que `srsue` corre): agregar una ruta por defecto dentro del netns del UE.
`srsue`'s `[gw]` crea `tun_srsue` con la IP asignada pero nunca agrega la ruta:

```bash
ip netns exec ue1 ip link set lo up
ip netns exec ue1 ip route add default via 10.45.1.1 dev tun_srsue
```

(el playbook lo hace automático, derivando el gateway de la IP asignada en vez de hardcodearlo)

## 3. Conectividad real: internet y `victim`, validada pasando por el UPF

Dos gaps de infraestructura reales en `core5g`, **nunca configurados hasta ahora** — el UE
llegaba a tener PDU Session pero cualquier tráfico salía con "Network is unreachable" o se
perdía en el camino:

1. **`FORWARD` en DROP por defecto** (cosa de Docker: inserta `DOCKER-USER`/`DOCKER-FORWARD`
   como primer salto de `FORWARD`, y `ogstun` — la interfaz de datos del UPF — no es una
   interfaz manejada por Docker, así que nunca matcheaba nada).
2. **Sin masquerade para el pool de UE** (`10.45.0.0/16`) — así que aunque se forwardeara, no
   había forma de que la respuesta volviera.

Arreglado con reglas idempotentes en `core5g_open5gs/tasks/main.yml` (`DOCKER-USER` ACCEPT para
`ogstun` en ambas direcciones + `MASQUERADE` del pool de UE saliendo por `ens160`, que cae
dentro del masquerade `10.10.0.0/24` que el control node ya tenía).

**Validado con evidencia real, no solo "el ping funcionó":**
- Internet: `ping -c 5 8.8.8.8` desde el netns del UE → 5/5, 0% pérdida. Captura simultánea con
  `tcpdump -i ogstun` en `core5g` → los 10 paquetes (5 request + 5 reply), ya desencapsulados de
  GTP-U, confirmando que el UPF está genuinamente en el camino.
- `victim` (10.10.0.100, dirección MGMT — la única alcanzable desde el pool de UE; la dirección
  ENT_DC de `victim` solo es alcanzable vía el bridge de `pe`, arquitectura distinta): 5/5,
  0% pérdida, RTT 129-253ms.

## 4. E2SM-KPM: subscribe+indicate con atribución real por UE

### 4.1. `xapp_kpm_moni` contra el RIC real (no el simulador ns-3)

Importante: `simulation/parse_xapp_kpm_log.py` y `ddos_xapp_events.csv` son de un pipeline
**distinto**, basado en ns-3 — no confundir con esto. Acá se usó el propio binario de ejemplo de
FlexRIC (`/opt/flexric/build/examples/xApp/c/monitor/xapp_kpm_moni`) contra el `nearRT-RIC` real
de la VM `ric`, suscrito al gNB real.

Dos bugs encontrados y arreglados en el camino (ambos ya en `gnb_zmq.yaml.j2`):

1. **`-a 127.0.0.1` cuelga para siempre** ("Resending Setup Request after timeout") — el
   `nearRT-RIC` solo bindea sus sockets SCTP (E2AP 36421, E42 36422) en su dirección real
   (`ric_addr`, confirmado vía `ss`/`lsof`), nunca en loopback. Hay que usar `-a {{ ric_addr }}`.
2. **`e2sm_rc_enabled: true` crashea el xApp** con un `assert()` fallido decodificando el
   service model RC (`rc_dec_asn.c:dec_ran_func_ctrl_it`, un campo ASN.1 no implementado en este
   build de FlexRIC) — pasa ANTES de que el xApp llegue siquiera a suscribirse a KPM. Como este
   lab no usa RIC Control, se deshabilitó (`e2sm_rc_enabled: false`).

### 4.2. Atribución por UE (Style 4/5, no solo agregado por celda)

Con el gNB arrancando limpio, las indicaciones SÍ llegaban, pero **ninguna traía identidad de
UE** — todas Format 1 (agregado de celda). Rastreado hasta el código real de srsRAN Project:

`e2sm_kpm_report_service_style4::collect_measurements()` → `get_ues_matching_test_conditions()`
→ solo devuelve UEs presentes en `ue_aggr_rlc_metrics` → ese mapa solo se llena vía
`report_metrics(rlc_metrics)` → ese callback solo se conecta en absoluto si
`metrics.layers.enable_rlc` es `true` en el YAML del gNB. Sin eso, `build_rlc_du_metrics()`
retorna temprano y **nunca crea nada** — ni el productor ni el consumidor que conecta con E2.
`metrics.periodicity.du_report_period` (necesario para el resto del pipeline de métricas) NO
alcanza solo — son dos flags separados.

**No hizo falta portar código de OCUDU** — era un gap de configuración real, no de wiring.

Confirmado con correlación temporal exacta (ping burst real mientras el xApp capturaba):

| Indicación | Tipo | `DRB.UEThpDl/Ul` |
|---|---|---|
| agregado (sin UE ID) | Style 1 | 49.00 / 59.00 kbps |
| **`UE ID = gNB-DU, gnb_cu_ue_f1ap = 0`** | Style 4 | **49.00 / 59.00 kbps — idénticos** |
| pico del burst (ambos) | — | 98.00 / 89.00 kbps |
| ping terminado (ambos) | — | 0.00 / 0.00 kbps |

## 5. Automatización

Playbooks en `deploy/vm-lab/ansible/playbooks/` (asumen que `site.yml` ya corrió, no compilan
nada — solo lanzan/prueban los binarios ya construidos):

```bash
cd deploy/vm-lab/ansible
ansible-playbook playbooks/test_single_ue.yml                     # §2 + §3
ansible-playbook playbooks/test_single_ue.yml -e victim_addr=X    # victim custom
ansible-playbook playbooks/test_kpm_validation.yml                # §4 (requiere §2 corrido antes)
ansible-playbook playbooks/test_three_ue_broker.yml                # §6 -- ver limitación abajo
```

## 6. Multi-UE (broker GNU-Radio): puede aislar 3 UEs reales, pero no de forma confiable

El camino multi-UE (`multi_ue_scenario.grc`, combina el UL de 3 UEs hacia el gNB y reparte el
DL) estaba documentado como roto entre VMs ("se cuelga después del handshake ZMQ"). Eso resultó
ser cierto solo parcialmente: **nunca se había corrido headless/en el orden correcto.**
`grcc` (persistido en `ue_srsue/tasks/main.yml`) compila el `.grc` a un script Python standalone
que corre bajo `xvfb-run` sin necesitar GUI — y con eso, sí corre.

### 6.1. Primer intento: no era un test de 3 UEs real — dos causas raíz reales

Con `test_three_ue_broker.yml` corriendo por primera vez: los 3 `srsue` reportaban
individualmente "RRC Connected" con el **mismo** `c-rnti=0x4601` y el **mismo** `tti=174`
exactos, pero el gNB solo veía una detección de PRACH y un contexto de UE. Dos causas reales,
ninguna en el `.grc`:

1. **`preamble_index` hardcodeado a `0` en srsRAN_4G.** `proc_ra_nr.cc`'s
   `ra_resource_selection()` (38.321 §5.1.2) está literalmente marcado `(TODO)` en su propio
   comentario — nunca implementa selección de preamble, así que TODOS los UEs, siempre,
   transmiten el preamble 0 en la ocasión 0. Bit-idénticos entre sí — ninguna lógica de
   combinación del broker podría distinguirlos. Arreglado con
   `srsran4g-random-preamble.patch` (`ue_srsue/files/`): aleatoriza `preamble_index` (seed por
   proceso, PID+tiempo), reseleccionado en cada reintento.
2. **`ue` con solo 2 vCPUs, 4x sobresuscrita.** Con 3 `srsue` + el broker corriendo DSP
   real-time simultáneo: `load average: 6.95`, 7-9 procesos en cola, 92-102k context-switches/s
   — mismo patrón que ya había forzado subir `ran` de 4 a 8 vCPUs (`f750440`). Redimensionado a
   8 vCPUs (`govc vm.change -vm ue -c 8`, tras `vm.power -off`/`-on`).

Efecto lateral encontrado al redimensionar: **un reboot borra los network namespaces** (viven en
`/var/run/netns`, tmpfs) — `ue1`'s propio `srsue` fallaba con "Failed to setup/configure GW
interface" porque su netns ya no existía. Arreglado con un servicio systemd oneshot
(`srsue-netns.service`) que los recrea en cada boot, sin depender de volver a correr Ansible.

### 6.2. Con ambos fixes: confirmado que SÍ puede aislar 3 UEs reales — pero no siempre

En una corrida real: **7 detecciones de PRACH genuinamente distintas** en el log del gNB
(`tc-rnti=0x4601` a `0x4607`, cada una con su propio `preamble` real), y **al menos 1 UE**
completando el attach entero (RACH → RRC Connected → RRC NR reconfiguration successful). El
broker no está fundamentalmente roto — puede darle a cada UE un canal de RF genuinamente
distinguible.

**Pero sigue siendo no-determinístico, y peor que el caso de 1 solo UE.** 4 corridas después del
fix: 1 éxito (7 PRACH/1 attach completo), 3 con 0 detecciones — comparado con el ~50% de
flakiness de RACH ya documentado para un solo UE (ver §2), esto parece contención adicional real
entre los 3 UEs, no solo la misma flakiness de siempre.

**Nuevo modo de fallo encontrado, distinto del original:** con la detección de PRACH ya
funcionando, UE2/UE3 SÍ consiguen que el gNB les detecte el preamble y les agende una ocasión de
PUSCH para el Msg3 (RRC Setup Request) — pero ese Msg3 llega con `crc=KO` sistemáticamente,
descartado tras 4 reintentos (`sinr=infdB`, un valor sospechoso). La detección de PRACH es
por correlación (tolerante a interferencia); el Msg3 es data real codificada, mucho más sensible.
Hipótesis, no confirmada: el broker suma las muestras de los 3 UEs en el dominio temporal sin
modelar un offset de timing/CFO por UE — necesario en OFDM real para que la ortogonalidad entre
subportadoras de transmisores simultáneos no se rompa. Arreglarlo necesitaría rediseñar esa
lógica de combinación en el `.grc` — no investigado más a fondo, es un trabajo de DSP más grande
que un patch puntual.

**Estado práctico: tratar "3 UEs reales" como posible pero no confiable.** Para cualquier prueba
que necesite conectividad real con más de un UE de forma consistente, seguir usando corridas
secuenciales de `test_single_ue.yml` en vez de depender del broker hasta que §6.2's modo de
fallo del Msg3 se resuelva.
