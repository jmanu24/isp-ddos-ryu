# Plan de instrumentación — Dominio Peering BGP (Fase E)

Estado: **mecanismo de mitigación confirmado de punta a punta, incluida la topología Mininet
real (§5) — FRR descartado, `flow` validado.** Pendiente: telemetría IPFIX real (§5 pasos 2-3)
y medición de efecto/TTL (§6). Referencia:
[Diseño de implementación](implementation-design.md) sección "Peering BGP" y fase E de la
tabla de módulos. Fecha: 2026-09-10/11.

## 1. Alcance y decisiones de despliegue confirmadas

Estas eran las "decisiones de despliegue aún necesarias" de `implementation-design.md` §8,
ya resueltas para este dominio:

| Decisión | Resuelto como | Nota |
|---|---|---|
| Software que instala FlowSpec en el plano de datos (en `r1`) | **[`flow`](https://github.com/hack3ric/flow)** (no FRR — ver §2) | FRR nunca fue capaz de instalar la ruta FlowSpec recibida como regla real de `nftables`/`iptables`; es un hueco conocido y sin resolver en FRR mainline desde 2019 ([FRRouting/frr#3160](https://github.com/FRRouting/frr/issues/3160)). `flow` sí lo hace — confirmado con evidencia real, ver §2. |
| Speaker BGP del lado del controlador | **`exabgp`**, vía su FIFO de comandos | Sin cambios respecto al diseño original — `exabgp` habla BGP con `flow`, no con FRR. |
| Telemetría de ingreso | **IPFIX real vía `softflowd`** | Más fiel a un borde SP real que nftables; introduce una herramienta nueva al proyecto. |
| Mecanismo de mitigación | **FlowSpec** (confirmado viable, ver §2) | Ya no es una apuesta — se validó con una regla real instalada en `nftables`. |
| Contrato de datos | **`TelemetryEvent`/`MitigationAction` actuales** | No se adelanta la Fase B (`core/observations.py`); si esa fase avanza, peering migra junto con los demás dominios, no antes. |
| Acción de mitigación | **`bgp_flowspec_discard` reemplaza a `bgp_blackhole`** | Simplifica a una sola acción de peering por ahora. RTBH queda fuera de alcance de esta fase. |

## 2. Spike de FlowSpec — resultado final: FRR falla, `flow` funciona

El soporte de traducir una ruta BGP FlowSpec recibida en una regla real de `nftables`/`iptables`
es una característica relativamente reciente y menos madura que el BGP básico — exactamente
el tipo de capacidad que `thesis-revision-plan.md` exige comprobar en el build desplegado,
no asumir de la documentación general. Se probaron dos rutas.

### 2.1. FRR — FAIL, causa raíz confirmada y documentada

`deploy/spike_flowspec_frr.sh` (conservado en el repo como evidencia negativa documentada,
no como script de despliegue) intentó validar `bgpd` + `zebra` de FRR como instalador. En el
camino se encontraron y resolvieron **cuatro problemas reales, independientes entre sí**,
antes de llegar a la causa raíz final:

1. **FRR prohíbe peering con `127.0.0.0/8` por diseño.** Un mantenedor de FRR lo confirma en
   [discusión #11375](https://github.com/FRRouting/frr/discussions/11375): *"we don't allow
   peering with 0.0.0.0/127.0.0.0/240.0.0.0 as they are treated as invalid ranges"*. Ningún
   ajuste de configuración lo evita.
2. **FRR también rechaza peering con cualquier IP local del mismo namespace de red**
   (`% Can not configure the local system as neighbor`), incluso usando un par `veth` con IPs
   no-loopback — hace falta aislar un extremo en su propio *network namespace* para que FRR
   lo trate como un sistema genuinamente distinto.
3. **`bgp ebgp-requires-policy` (cumplimiento de RFC 8212)** descarta silenciosamente todas
   las rutas entrantes de un vecino eBGP sin política explícita — la sesión se establece pero
   `show bgp ipv4 flowspec` muestra 0 rutas.
4. **La configuración de `bgpd` armada por `vtysh` no persiste** entre reinicios de `frr` sin
   `write memory` — un reinicio (necesario para activar el daemon `pbrd`) la borró por completo.

Superados los cuatro, la ruta SÍ llegó a la RIB de FlowSpec (`show bgp ipv4 flowspec`) y
`show pbr ipset`/`show pbr iptable` (la vista *interna* de FRR) mostraban el objeto de la
regla correctamente armado. Pero el sistema real (`iptables -S`, `ipset list`) nunca mostró
nada, con o sin `pbrd` habilitado. Causa raíz, confirmada por un mantenedor de FRR en
[FRRouting/frr#3160](https://github.com/FRRouting/frr/issues/3160) (abierto en 2019, **sin
resolver** a la fecha, reportado también en 7.0, 7.5.1, 8.1.0 y 8.4.2):

> **pguibert6WIND** (mantenedor, FRR/6WIND): *"the PBR install requires FRR to contain a
> plugin that is not yet in FRR main stream"* ... *"we have to go to a real ABI (application
> BINARY interface), if someone is willing to do it."*

Es decir: el puente FlowSpec→PBR→kernel de FRR construye el objeto de la regla en memoria,
pero el código que lo empujaría al kernel real **nunca se integró a la rama principal**. No
es un error de configuración nuestro ni algo que un spike más largo fuera a resolver.

### 2.2. `flow` — PASS, confirmado con evidencia real

[`hack3ric/flow`](https://github.com/hack3ric/flow) no es un router BGP completo — es un
*sink* que recibe una sesión BGP de otro speaker (en nuestro caso, `exabgp`) y traduce las
rutas FlowSpec recibidas en reglas `nftables` reales vía `rtnetlink(7)`. Es exactamente el
puente que a FRR le falta. Instalación vía binario precompilado (`x86_64-unknown-linux-gnu`,
sin necesidad de compilar Rust — ver `deploy/install_bgp_peering.sh`).

A diferencia de FRR, `flow` no tiene ninguna de las cuatro restricciones de la sección 2.1:
es pasivo por diseño (nunca inicia la sesión, evitando colisiones), y su propio ejemplo de
uso oficial ya empareja sobre loopback (`::1`) sin problema. La sesión `exabgp` ↔ `flow` se
estableció **al primer intento**, sin ningún ajuste especial.

Ruta de prueba: `announce flow route { match { destination 198.51.100.99/32; protocol tcp;
destination-port =80; } then { discard; } }` vía el FIFO de `exabgp`. Resultado, verificado
directamente en el sistema (no en la vista interna de una herramienta):

```
$ sudo ip netns exec exabgp-ns nft list ruleset
table inet flowspecs {
        chain flowspecs {
                ip daddr 198.51.100.99 meta l4proto { tcp } th dport { 80 } drop comment "0"
        }
}
```

Regla real, en `nftables`, instalada automáticamente a partir de la ruta BGP FlowSpec
anunciada. **Esto es la prueba de capacidad que exige `implementation-design.md` §5** (más
allá de ACCEPTED/DISPATCHED — esto es una instalación real verificada).

**Ciclo de retiro también confirmado.** Se probó `withdraw flow route { ... }` (mismo match)
sobre la misma sesión: `flow show` dejó de listar la ruta, y `nft list ruleset` volvió a
mostrar la cadena `flowspecs` vacía — la regla real fue removida, no solo desasociada de la
vista de `flow`. El ciclo completo announce→instalación→withdraw→remoción queda confirmado
de punta a punta. Automatizado en `deploy/spike_flowspec_flow.sh` (pasos 7-8). Lo único que
sigue pendiente es la medición de *efecto* sobre tráfico real y la integración con `r1`/la
topología Mininet (ver §5/§6).

**Honestidad a mantener en la tesis:** `flow` es una herramienta joven y su propio README lo
advierte — *"has yet to be tested thoroughly and not suitable for production for now"* (30
estrellas, mantenedor único). Válida y documentada como tal para un testbed de laboratorio;
no presentar como una solución de nivel productivo.

Reproducible con `deploy/spike_flowspec_frr.sh` (documenta el FAIL, conservado como evidencia)
y el procedimiento de `flow` reproducido en `deploy/spike_flowspec_flow.sh` (documenta el PASS).

### 2.3. Telemetría (`peer_ext` → `softflowd` → `nfcapd` → `nfdump` → collector) — PASS

Confirmado de punta a punta en la VM (`validate_peering.py`, paso 6) el 2026-09-11, tras varias
rondas de debugging real que vale documentar porque cada una fue una causa raíz distinta, no
una sola:

1. **Un ping simple nunca llega a exportarse.** `softflowd` reportó "Flows: 0" incluso con
   ICMP real confirmado por `tcpdump` en la misma interfaz. `softflowctl statistics` aisló la
   causa: `Packets received by libpcap` > 0 pero `Packets processed: 0` — el *ring buffer* de
   captura de Linux (TPACKET_V3) solo entrega paquetes a `softflowd` cuando se llena un bloque
   completo, y `softflowd` no fija un *timeout* de lectura ni modo inmediato, así que un puñado
   de pings nunca dispara el volcado. La causa **no** es específica de ICMP ni de la versión de
   NetFlow (se descartó explícitamente probando v9 y v5 con el mismo resultado). El build de
   `softflowd` 1.0.0 de esta VM tampoco soporta `-B` (tamaño de buffer) para mitigarlo desde ahí.
   **Fix:** `validate_peering.py` genera tráfico real con `hping3 --icmp --flood` (mismo patrón
   ya usado en el dominio enterprise) en vez de un ping — volumen suficiente para llenar un
   bloque de inmediato, y además representa mejor lo que esta tubería existe para detectar.
2. **`collectors/peering_flow_collector.py` nunca lee el último archivo de `nfcapd`** por
   diseño (asume que `nfcapd` lo tiene abierto — correcto para el polling continuo del
   orchestrator en producción). En una prueba de una sola pasada, si solo ocurre una rotación
   antes de consultar al colector, el archivo con los datos reales queda excluido para siempre.
   **Fix:** esperar dos ciclos de rotación de `nfcapd`, no uno, antes de invocar `poll()`.
3. `nfdump -o csv` agrega un bloque `Summary` final con columnas distintas a las de un flujo
   real; `csv.DictReader` lo mapea por posición sobre el header original, dejando columnas más
   allá del ancho del resumen (como `ipkt`) en `None`, y `int(None)` lanza `TypeError` — no
   capturado por el `except (KeyError, ValueError)` existente. Nunca se había manifestado
   porque todo archivo de captura anterior estaba vacío ("No matched flows", sin bloque
   `Summary`). **Fix:** agregar `TypeError` al `except`.
4. Un `flow` matado con `pkill -9` durante la limpieza manual de la VM no alcanza a borrar su
   propio socket de control (nombre determinístico según IP:puerto de bind), y la siguiente
   corrida falla con `Address already in use`. **Fix:** `PeeringLifecycle.start()` limpia
   sockets viejos en `/run/flow/*.sock` antes de arrancar `flow`, igual que ya crea el FIFO de
   `exabgp` si no existe.

De paso, se agregó `PeeringLifecycle._ensure_alive()`: cada uno de los 4 subprocesos
(`flow`/`exabgp`/`nfcapd`/`softflowd`) se verifica vivo justo después de arrancar, y lanza una
excepción inmediata con el log si ya murió — antes, un flag de CLI rechazado (como el `-B` de
softflowd, no soportado en el build de esta VM) fallaba en silencio y solo se notaba varios
pasos después como "no hay datos de telemetría", sin ninguna pista de la causa real.

Adicionalmente se encontró y corrigió un segundo bug real vía las mismas pruebas: un `nfcapd`
matado con `pkill -9` (limpieza manual entre sesiones de prueba) deja su archivo
`nfcapd.current.<PID>` huérfano — nunca se renombra a su nombre final con timestamp porque eso
solo ocurre en una rotación limpia. Peor aún, `PeeringFlowCollector` arrancaba con
`_processed_files` vacío, así que el primer `poll()` de una sesión nueva del controlador leía
*todo* archivo `nfcapd.*` preexistente como si fuera tráfico en vivo — confirmado en la VM: al
arrancar el controlador (antes de que la topología, y por tanto `flow`/`exabgp`, existieran) se
disparó una detección y un intento de mitigación FlowSpec real usando datos de horas antes,
fallando al escribir al FIFO de exabgp (`ENXIO`, sin lector activo). **Fix:**
`PeeringFlowCollector.__init__` ahora siembra `_processed_files` con lo que ya exista en el
directorio al construirse — semántica "tail -f", no "leer todo el historial".

### 2.4. Limitación arquitectónica encontrada: el dominio `bgp` casi nunca "gana" la
representación en `detection/engine.py`

Al probar el dominio desde el webtool real (`peer_ext` atacando un host normal de la topología,
detrás de un switch), el log del controlador mostró la detección y mitigación etiquetadas como
`[enterprise]` (`DROP_RULE_INSTALLED ... scope=4 switch(es)`), **nunca** `[bgp]`
(`BGP_FLOWSPEC_DISCARD`) — pese a que la tubería de telemetría BGP (§2.3) sí capturó el mismo
tráfico real (confirmado revisando los archivos `nfcapd.*` generados durante la ventana del
ataque).

Causa raíz: `correlation/correlator.py` agrupa eventos de telemetría por `dst_ip`, sin importar
el dominio que los reportó — así que el mismo tráfico externo hacia un host interno es visto
*tanto* por `enterprise` (vía OpenFlow, en el switch) *como* por `bgp` (vía `nfcapd` en
`r1-ext0`, antes de llegar al switch). `detection/engine.py`'s `_pick_representative()` decide
cuál de los dos "gana" el `DetectionResult.domain` (y por tanto qué mecanismo de mitigación se
usa, ver `orchestration/controller.py`'s `_action_for()`), y **siempre prefiere un evento con
`in_port` real** (solo lo tiene un evento derivado de OpenFlow packet-in) **sobre uno derivado
de flow-stats** (lo único que puede producir el adaptador `bgp`, ya que `nfcapd` nunca reporta
un puerto OpenFlow). Es una regla deliberada y razonable en general (permite acotar el bloqueo
al switch+puerto más cercano al atacante real), pero tiene como efecto colateral que **mientras
el destino esté detrás de cualquier switch, el dominio `bgp` nunca puede ganar la
representación** — sin importar que su propia telemetría sí detecte el ataque.

El único destino donde `bgp` sí gana es `central_server` (10.99.0.1): es una interfaz *dummy*
directamente en `r1` (`topologies/star_topology.py`'s `add_central_server`), nunca observada
por ningún switch, así que no compite con ningún evento de `enterprise`. **Decisión tomada**:
por ahora, validar el camino real `BGP_FLOWSPEC_DISCARD` a través del motor de detección
atacando `central_server` desde `peer_ext` (el webtool ya lo permite como objetivo — el filtro
del dropdown de objetivos en `webtool/static/app.js` excluía `domain === "core"` pese a que
`orchestrator.py`'s `valid_targets()` ya lo permitía; corregido para incluirlo). Queda como
limitación arquitectónica conocida, no resuelta: un ataque externo real contra cualquier host
normal de la topología (el escenario más realista) seguirá mitigándose como bloqueo OpenFlow de
red completa, no como descarte BGP FlowSpec en el borde. Cambiar `_pick_representative()` para
que un origen externo (`bgp`) gane sobre `in_port` es la opción evaluada y pospuesta
deliberadamente -- afecta la lógica de correlación para todos los dominios, no solo `bgp`, y
merece su propia decisión de diseño antes de tocarla.

## 3. Módulos nuevos y su responsabilidad

```mermaid
flowchart LR
    subgraph r1[r1 -- flow: recibe FlowSpec, instala en nftables]
        SF[softflowd] -->|IPFIX| COL
    end
    COL[collectors/peering_flow_collector.py] --> ADAPT[telemetry/bgp_adapter.py]
    ADAPT --> DET[DDoSDetectionEngine]
    DET --> ORCH[orchestration/controller.py]
    ORCH -->|MitigationAction bgp_flowspec_discard| BACK[mitigation/peering_backend.py]
    BACK -->|exabgp anuncia/retira NLRI FlowSpec vía BGP| r1
    r1 -->|instala/retira regla real, vía rtnetlink| DATAPLANE[nftables en r1]
```

| Módulo | Responsabilidad | Notas de implementación |
|---|---|---|
| `collectors/peering_flow_collector.py` (nuevo) | Recibir/parsear registros IPFIX de `softflowd` y producir eventos por flujo (src/dst/proto/puerto/bytes/paquetes). | **No reutiliza** `collectors/flow_collector.py` — ese colector está atado al formato de FlowStats de OpenFlow/Ryu. Necesita su propio parser IPFIX (evaluar librería: `ipfix`, `pyflowkit`, o parseo directo del formato). |
| `telemetry/bgp_adapter.py` (reemplaza el stub) | `collect()` lee del colector anterior y produce `TelemetryEvent` con `domain="bgp"`. `is_connected()` verifica sesión BGP activa con `flow` en `r1` (vía el backend de mitigación, ver abajo) y/o que `softflowd` esté exportando. | Mantiene la forma actual de `DomainAdapter`; no cambia de contrato. |
| `mitigation/peering_backend.py` (implementado, ver §2.2) | Actúa como BGP speaker (`exabgp`, vía FIFO): origina/retira rutas FlowSpec hacia `flow` en `r1`. Traduce `MitigationAction(action="bgp_flowspec_discard")` → NLRI FlowSpec (match dst/proto/puerto, acción descarte) y su retiro al expirar TTL. | Confirmado funcional contra `flow` (§2.2). `telemetry/bgp_adapter.py.apply_mitigation()` delega aquí. |

## 4. Cambios en código existente

- `orchestration/controller.py:629-633`, método `_action_for()`: cambiar
  `if domain == "bgp": return "bgp_blackhole"` → `return "bgp_flowspec_discard"`. **Hecho.**
- `core/models.py:101`: actualizar el docstring de `MitigationAction.action` para reflejar
  `"block" | "rate_limit" | "bgp_flowspec_discard"` (retirando `bgp_blackhole`). **Hecho.**
- `webtool/static/app.js:318` (`BLOCK_DOMAIN_LABELS`): ya tiene `bgp: "BGP"` — sin cambios
  necesarios, pero verificar que la UI de bloqueos activos muestre la acción correcta una
  vez que `bgp_flowspec_discard` empiece a aparecer en logs/estado real.
- `topologies/star_topology.py`: **hecho.** `attach_peering_uplink_to_r1()` da a `r1` una
  interfaz real (`10.98.0.2`, veth) alcanzable desde el namespace raíz (`10.98.0.1`), mismo
  patrón que `attach_bng_gateway_to_r1`.
- `webtool/peering_ops.py` (nuevo): **hecho, sin validar en la VM todavía.** `PeeringLifecycle`
  arranca `flow` dentro del namespace de `r1` (vía `r1.popen`, escuchando en `10.98.0.2:179`)
  y `exabgp` en el namespace raíz (junto al propio controlador Ryu), generando su
  `exabgp.conf` apuntando a esa dirección. Cableado en `webtool/orchestrator.py`'s
  `start_topology()`/`stop_topology()`, simétrico a como ya maneja BNG.

## 5. Orden de entrega

1. ~~Spike de validación FlowSpec en FRR~~ **Resuelto (§2): FRR descartado, `flow`
   confirmado con una regla real en `nftables`.**
2. ~~Instalar y configurar `softflowd` en la interfaz externa de `r1`~~ **Confirmado en la VM
   (2026-09-11, §2.3): nuevo host `peer_ext` (`topologies/star_topology.py`'s
   `attach_external_peer`, enlazado directo a `r1`, no vía switch — representa tráfico
   externo/upstream, la misma decisión de diseño que `ent_i`/`gnb_i`/`fixed_i` para sus
   propios dominios) + `softflowd`/`nfcapd` corriendo dentro del namespace de `r1`
   (`webtool/peering_ops.py`, igual que `flow`), exportando por loopback interno de `r1` con
   rotación cada 5s (no los 300s por defecto de `nfcapd` — demasiado lento para la cadencia de
   detección del proyecto).**
3. `collectors/peering_flow_collector.py` + `telemetry/bgp_adapter.py`: **ya existían** desde
   la instrumentación inicial (ver §3) — **confirmado en la VM (§2.3) que `nfdump -o csv`
   realmente produce el formato que el parser asume (campos `sa`/`da`/`dp`/`pr`/`td`/`ipkt`/
   `ibyt`), antes probado solo con datos sintéticos.** Paso 6 de `validate_peering.py` corre el
   pipeline completo (`peer_ext` → `softflowd` → `nfcapd` → `PeeringFlowCollector.poll()`) y
   pasa de punta a punta.
4. ~~Integrar `flow` dentro de la topología Mininet~~ **Confirmado en la VM (2026-09-11):**
   `build_topology()` + `PeeringLifecycle.start()` real (sin FRR, sin namespace aislado) —
   sesión `exabgp`↔`flow` establecida sobre `10.98.0.1`↔`10.98.0.2` (el enlace de
   `attach_peering_uplink_to_r1`), y el ciclo `announce`→regla real en `nft list ruleset`
   dentro de `r1`→`withdraw`→regla removida, confirmado con `r1.cmd("nft list ruleset")`
   antes y después. Teardown (`peering.stop()` + `net.stop()`) limpio, sin errores.
   Formalizado como `validate_peering.py` (raíz del repo, mismo patrón que
   `validate_phase1.py`) — `sudo python3 validate_peering.py` reproduce esta validación.
5. Actualizar los 3 puntos de código existente (§4) y el webtool. **Hecho** salvo
   `webtool/static/app.js` (sin cambios necesarios, ver nota en §4).
6. Escenario de ataque end-to-end contra el dominio peering (uno de los "24 casos básicos"
   de la matriz de `thesis-revision-plan.md`), con medición de Td/Tdispatch/Tapply/Tefecto.

## 6. Criterio de salida de la fase (igual al de `implementation-design.md` §6)

**"Router instala y retira política; efecto medido."** La instalación y el retiro reales ya
están confirmados tanto en el spike aislado (§2.2) como dentro de la topología Mininet real
(§5, paso 4) — `announce`/`withdraw` verificados con regla real de `nftables` apareciendo y
desapareciendo en el `r1` de verdad. La telemetría real (§2.3) también queda confirmada de
punta a punta: `peer_ext` → `softflowd` → `nfcapd` → `nfdump` → `PeeringFlowCollector`. No
declarar la fase E completa mientras falte:
- Confirmar el retiro por **expiración de TTL** desde `mitigation/peering_backend.py`
  (`MitigationAction.duration`), no solo por un `withdraw` manual vía FIFO como en las pruebas.
- Medir el *efecto* real: tráfico generado hacia el destino bajo mitigación efectivamente cae
  a cero mientras la regla está activa (las pruebas hasta ahora confirman que la regla existe
  en `nftables`, no que descarta tráfico real observado end-to-end).
- El escenario de ataque end-to-end (§5, punto 6) debe atacar `central_server`, no un host
  normal de la topología, para que el motor de detección real elija `bgp` como dominio
  representante (ver §2.4) — atacar cualquier otro destino se mitiga hoy como bloqueo OpenFlow
  de red completa, no como `BGP_FLOWSPEC_DISCARD`.
