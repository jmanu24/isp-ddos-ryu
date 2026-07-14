# Plan de pruebas — webtool (Fases 1-3)

Runbook manual para validar, contra una VM real (Ubuntu 20.04, Mininet +
hping3 + bngblaster + nft instalados), los 5 escenarios pedidos. Usa
únicamente la API REST de `webtool/app.py` (puerto 5050) vía `curl` — no
requiere el frontend, aunque cualquier paso se puede reproducir también
desde el navegador (`http://<ip-vm>:5050/`).

Convención de IPs (topologies/star_topology.py): `ent_i`=`10.0.i.10`,
`gnb_i`=`10.0.i.20`, `fixed_i`=`10.0.i.30`, servidor central=`10.99.0.1`
(el destino habitual del tráfico benigno de los 12 hosts, y también un
objetivo de ataque válido — ver escenario 5b para el caso multi-dominio).

## 0. Preparación (una sola vez por sesión de pruebas)

```bash
cd ~/isp-ddos-ryu
git pull
sudo pkill -9 -f hping3; sudo pkill -9 bngblaster; sudo pkill -9 dnsmasq 2>/dev/null
sudo mn -c
sudo ./deploy/setup_bng_netns.sh --teardown
sudo python3 webtool/app.py   # dejar corriendo en su propia terminal
```

En otra terminal:

```bash
curl -X POST localhost:5050/api/controller/start
curl -X POST localhost:5050/api/topology/start
curl -s localhost:5050/api/topology/status | python3 -m json.tool   # confirmar 15 nodos, status=running
```

Abrir una tercera terminal con el log del controlador en vivo — se usa
en todos los escenarios:

```bash
tail -f /tmp/webtool_controller.log
```

**Nota de reinicio**: si en el medio de las pruebas hacés `git pull` de
un cambio en `webtool/*.py` o `telemetry/broadband_adapter.py`, hay que
reiniciar `webtool/app.py` completo (Ctrl-C, esperar el mensaje
`[webtool] apagando...`, volver a lanzarlo) — un cambio en
`controller/ryu_controller_2.py` o en cualquier `telemetry/*_adapter.py`
solo necesita reiniciar el controlador (`/api/controller/stop` +
`/api/controller/start`), no la app entera.

---

## Escenario 1 — Todos los nodos activos, tráfico legítimo

**Objetivo**: confirmar que el baseline benigno (loops ICMP de
enterprise/mobile, sesiones `low_and_slow` de broadband) fluye desde los
12 hosts hacia el servidor central sin disparar ninguna detección falsa.

1. Con la topología recién iniciada (paso 0) y **sin lanzar ningún
   ataque**, esperar 90 segundos.
2. Verificar que no hay eventos de detección:
   ```bash
   grep -c "DETECTION" /tmp/webtool_controller.log   # debe dar 0 (o solo detecciones de pruebas previas, si no reiniciaste el log)
   curl -s localhost:5050/api/attacks | python3 -m json.tool   # debe ser []
   ```
3. Confirmar tráfico real llegando al servidor central (una muestra de
   20 paquetes basta, de cualquier dominio):
   ```bash
   sudo timeout 15 tcpdump -i r1-central0 -nn -c 20
   ```
   Se deben ver orígenes `10.0.x.10` (enterprise), `10.60.x.2` (UE
   benigna de mobile) y, indirectamente, la sesión `low_and_slow` de
   broadband (verificable en cambio con `sudo mnexec -a $(pgrep -f
   'mininet:r1'|head -1) nft -j list table inet ue_acct` para el lado
   mobile, o revisando `/tmp/ddos_bng_events.csv` para broadband).
4. **Criterio de éxito**: 0 líneas `DETECTION` en el log, `active_attacks`
   vacío, tráfico visible desde múltiples orígenes hacia `10.99.0.1`.

---

## Escenario 2 — TCP SYN Flood por dominio (individual)

Mismo patrón para los 3 dominios — un solo nodo atacante, duración 20s
(auto-stop), verificar `DETECTION` → `BLOCK`/`THROTTLE` → `UNBLOCK`/
`UNTHROTTLE` en el log.

### 2a. Enterprise (`ent_1` → `ent_3`)
```bash
curl -s -X POST localhost:5050/api/attack/start -H 'Content-Type: application/json' \
  -d '{"domain":"enterprise","switch_indices":[1],"attack_type":"SYN","target_ip":"10.0.3.10","duration":20}'
```
Esperar 20-90s, luego:
```bash
grep '\[enterprise\]' /tmp/webtool_controller.log | tail -10
```
Esperado: `DETECTION: ATTACK_DETECTED SYN_FLOOD source=10.0.1.10 destination=10.0.3.10:443/TCP`,
`MITIGATION: BLOCK ...`, y (dentro de ~90s) `MITIGATION: UNBLOCK ...`.

### 2b. Mobile (`gnb_2` → `ent_3`)
```bash
curl -s -X POST localhost:5050/api/attack/start -H 'Content-Type: application/json' \
  -d '{"domain":"mobile","switch_indices":[2],"attack_type":"SYN","target_ip":"10.0.3.10","duration":20}'
```
```bash
grep '\[mobile\]' /tmp/webtool_controller.log | tail -10
```
Esperado: `DETECTION: ATTACK_DETECTED SYN_FLOOD source=10.60.2.x ...`, `MITIGATION: THROTTLE ...`.
(mobile no tiene UNBLOCK automático inmediato — se libera cuando el
proceso atacante se detiene y dtelemetry dejar de reportar hacia ese
destino, ver `check_mobile_unblocks`.)

### 2c. Broadband (sesión única → `ent_4`)
```bash
curl -s -X POST localhost:5050/api/attack/start -H 'Content-Type: application/json' \
  -d '{"domain":"broadband","switch_indices":[3],"attack_type":"SYN","target_ip":"10.0.4.10","duration":20}'
```
```bash
grep '\[broadband\]' /tmp/webtool_controller.log | tail -10
```
Esperado: `DETECTION: ATTACK_DETECTED SYN_FLOOD source=10.61.1.14x ...`, `MITIGATION: BLOCK ...`,
y `UNBLOCK` ~60s después del bloqueo (ventana fija, dominio
presence-blind). Confirmar también que `/tmp/bng_dhcp_blacklist.hosts`
vuelve a quedar vacío tras el `UNBLOCK`.

**Criterio de éxito (2a-2c)**: cada sub-test muestra `DETECTION` +
mitigación con la etiqueta de dominio correcta (nunca `[enterprise]`
detectando tráfico de mobile/broadband ni viceversa), y el bloqueo se
libera automáticamente sin intervención manual.

---

## Escenario 3 — UDP Flood por dominio (individual)

Mismo patrón, cambiando `attack_type` a `"UDP"`. Rotar atacante/objetivo
para no repetir exactamente el mismo par que en el escenario 2:

### 3a. Enterprise (`ent_2` → `ent_4`)
```bash
curl -s -X POST localhost:5050/api/attack/start -H 'Content-Type: application/json' \
  -d '{"domain":"enterprise","switch_indices":[2],"attack_type":"UDP","target_ip":"10.0.4.10","duration":20}'
```

### 3b. Mobile (`gnb_3` → `ent_1`)
```bash
curl -s -X POST localhost:5050/api/attack/start -H 'Content-Type: application/json' \
  -d '{"domain":"mobile","switch_indices":[3],"attack_type":"UDP","target_ip":"10.0.1.10","duration":20}'
```

### 3c. Broadband (sesión única → `ent_2`)
```bash
curl -s -X POST localhost:5050/api/attack/start -H 'Content-Type: application/json' \
  -d '{"domain":"broadband","switch_indices":[1],"attack_type":"UDP","target_ip":"10.0.2.10","duration":20}'
```

Verificar cada uno igual que en el escenario 2 (`grep '\[<dominio>\]'`),
buscando `UDP_FLOOD` en vez de `SYN_FLOOD`.

**Criterio de éxito**: igual al escenario 2, con `attack_type=UDP_FLOOD`
en las líneas de log.

---

## Escenario 4 — ICMP Flood por dominio (individual)

### 4a. Enterprise (`ent_4` → `ent_1`)
```bash
curl -s -X POST localhost:5050/api/attack/start -H 'Content-Type: application/json' \
  -d '{"domain":"enterprise","switch_indices":[4],"attack_type":"ICMP","target_ip":"10.0.1.10","duration":20}'
```

### 4b. Mobile (`gnb_1` → `ent_2`)
```bash
curl -s -X POST localhost:5050/api/attack/start -H 'Content-Type: application/json' \
  -d '{"domain":"mobile","switch_indices":[1],"attack_type":"ICMP","target_ip":"10.0.2.10","duration":20}'
```

### 4c. Broadband (sesión única → `ent_3`)
```bash
curl -s -X POST localhost:5050/api/attack/start -H 'Content-Type: application/json' \
  -d '{"domain":"broadband","switch_indices":[2],"attack_type":"ICMP","target_ip":"10.0.3.10","duration":20}'
```

**Nota enterprise/ICMP**: en pruebas previas, un flood ICMP enterprise
generó DOS detecciones (ida y vuelta — el destino también responde a
volumen alto de echo-request con echo-reply suficiente para cruzar el
umbral en sentido inverso). Esto es esperado, no un bug: confirmar que
ambos sentidos terminan con `UNBLOCK`.

**Criterio de éxito**: igual a los escenarios 2/3, con `ICMP_FLOOD`.

---

## Escenario 5 — TCP SYN distribuido

### Limitaciones a tener en cuenta antes de correr este escenario

- **Enterprise**: la topología en estrella solo tiene **1 host
  enterprise por switch** (4 switches = máximo 4 fuentes reales
  distintas). `DIST_MIN_SOURCES=5` en `config/settings.py` — con solo 4
  fuentes, el motor de detección **no** debería clasificar esto como
  `DDOS_DISTRIBUTED`; lo esperable es ver hasta 4 `SYN_FLOOD`
  individuales (uno por atacante) en vez de una única detección
  distribuida. Documentado como comportamiento esperado, no como falla.
- **Broadband**: soportado vía `attack_type: "SYN_DISTRIBUTED"` (mapea a
  `distributed_syn_flood` en `simulation/bng_config.py`, 8 sesiones,
  ~5 pps cada una). Sigue siendo **una sola instancia real de
  bngblaster** -- `switch_indices` en la petición es solo una etiqueta
  cosmética (ver `webtool/bng_ops.py`'s `session_switch_label()`), no
  separa las 8 sesiones por switch de verdad.
- **Mobile**: sin esta limitación — `count_per_node` permite superar
  `DIST_MIN_SOURCES=5` fácilmente desde un solo gNB o repartido entre
  varios.

### 5a. Distribuido dentro de un mismo dominio

**Enterprise (4 fuentes — por debajo del umbral, resultado esperado:
detecciones individuales, no DDOS_DISTRIBUTED):**
```bash
curl -s -X POST localhost:5050/api/attack/start -H 'Content-Type: application/json' \
  -d '{"domain":"enterprise","switch_indices":[1,2,3,4],"attack_type":"SYN","target_ip":"10.0.1.30","duration":25}'
```
```bash
grep '\[enterprise\]' /tmp/webtool_controller.log | tail -20
```
Esperado: hasta 4 líneas `DETECTION: ATTACK_DETECTED SYN_FLOOD` con
`source=10.0.{1,2,3,4}.10` (no una sola `DDOS_DISTRIBUTED`).

**Mobile (6 UEs repartidas en 2 gNBs — por encima del umbral):**
```bash
curl -s -X POST localhost:5050/api/attack/start -H 'Content-Type: application/json' \
  -d '{"domain":"mobile","switch_indices":[1,3],"attack_type":"SYN","target_ip":"10.0.2.30","count_per_node":3,"duration":25}'
```
```bash
grep '\[mobile\]' /tmp/webtool_controller.log | tail -20
```
Esperado: `DETECTION: ATTACK_DETECTED DDOS_DISTRIBUTED` (o varias
`SYN_FLOOD` seguidas de una clasificación distribuida, según el ciclo de
detección) con al menos 5 fuentes distintas `10.60.{1,3}.x`, seguido de
`MITIGATION: THROTTLE` por cada UE contribuyente (`_build_actions` emite
una acción por fuente para `DDOS_DISTRIBUTED` en dominios
`PER_SOURCE_MITIGATION_DOMAINS`).

**Broadband (8 sesiones reales, distributed_syn_flood):**
```bash
curl -s -X POST localhost:5050/api/attack/start -H 'Content-Type: application/json' \
  -d '{"domain":"broadband","switch_indices":[4],"attack_type":"SYN_DISTRIBUTED","target_ip":"10.0.3.30","duration":30}'
```
```bash
grep '\[broadband\]' /tmp/webtool_controller.log | tail -20
```
Esperado: `DETECTION: ATTACK_DETECTED DDOS_DISTRIBUTED` con 8 fuentes
`10.61.1.14x` (una por sesión BNG), seguido de `MITIGATION: BLOCK` por
sesión contribuyente. Al terminar, el `BngLifecycle` vuelve solo al
baseline `low_and_slow` (confirmar con `tail -f` en la terminal de
`webtool/app.py`: debería verse un nuevo `[BNG] launching ...
scenario=low_and_slow`).

### 5b. Distribuido entre dominios, contra el servidor central (MULTIDOMAIN_DISTRIBUTED_ATTACK)

El servidor central (`10.99.0.1`) es un objetivo válido (`orchestrator.
valid_targets()` lo incluye siempre que la topología esté arriba).
`correlation/correlator.py` ya agrupa telemetría por `dst_ip` sin
importar el dominio, así que si los 3 dominios atacan la MISMA IP con
el mismo protocolo, `detection/engine.py` los ve como una sola
`CorrelatedEvent` y, si las fuentes combinadas superan
`DIST_MIN_SOURCES=5` con suficiente entropía, clasifica **una única**
detección `MULTIDOMAIN_DISTRIBUTED_ATTACK` (en vez de `DDOS_DISTRIBUTED`,
reservado para cuando todas las fuentes contribuyentes son del mismo
dominio) — y `orchestration/controller.py` reparte la mitigación
correspondiente a cada dominio real de cada fuente (bloqueo OpenFlow
para las IPs de `ent_i`, kill de proceso via cola RC para las UEs
`10.60.x.x`, `session-stop`+blacklist DHCP para las sesiones BNG
`10.61.1.14x`), no todo por un solo mecanismo:

```bash
curl -s -X POST localhost:5050/api/attack/start -H 'Content-Type: application/json' \
  -d '{"domain":"enterprise","switch_indices":[1,2,3,4],"attack_type":"SYN","target_ip":"10.99.0.1","dst_port":443,"duration":30}' &
curl -s -X POST localhost:5050/api/attack/start -H 'Content-Type: application/json' \
  -d '{"domain":"mobile","switch_indices":[1,2,3,4],"attack_type":"SYN","target_ip":"10.99.0.1","dst_port":443,"count_per_node":2,"duration":30}' &
curl -s -X POST localhost:5050/api/attack/start -H 'Content-Type: application/json' \
  -d '{"domain":"broadband","switch_indices":[1],"attack_type":"SYN_DISTRIBUTED","target_ip":"10.99.0.1","duration":30}' &
wait
```
```bash
curl -s localhost:5050/api/attacks | python3 -m json.tool   # deben verse los 3 ataques activos a la vez
grep -E '\[enterprise\]|\[mobile\]|\[broadband\]' /tmp/webtool_controller.log | tail -40
```

20 fuentes distintas entre los 3 dominios (4 enterprise + 8 UEs móviles
+ 8 sesiones BNG), muy por encima de `DIST_MIN_SOURCES=5` incluso
contando un solo dominio a la vez, para que la naturaleza multi-dominio
del veredicto no sea un artefacto de necesitar los 3 para llegar al
mínimo.

**Advertencia de entropía**: `DIST_ENTROPY_THRESHOLD=0.7` exige una
distribución de pps pareja entre fuentes. Enterprise/mobile usan
`--flood` (tasa real sin techo, no parametrizable via la API hoy);
broadband's `distributed_syn_flood` es una tasa fija (~5 pps/sesión).
Si la tasa de un dominio domina desproporcionadamente el total, la
entropía puede no alcanzar 0.7 y el ataque podría clasificar distinto
a lo esperado (o no clasificar como distribuido en absoluto). Si esto
pasa, probar reduciendo la cantidad de fuentes enterprise/mobile (p.ej.
2 switches enterprise + `count_per_node:1` en 2 switches mobile) antes
de asumir que la lógica de clasificación está mal.

**Criterio de éxito**: **una sola** línea `DETECTION: ATTACK_DETECTED
MULTIDOMAIN_DISTRIBUTED_ATTACK source=* destination=10.99.0.1:443/TCP`
(no tres detecciones separadas), seguida de líneas `MITIGATION: BLOCK
MULTIDOMAIN_DISTRIBUTED_ATTACK` con `source=` reales de **cada uno**
de los 3 dominios (`10.0.x.10` enterprise, `10.60.x.x` mobile,
`10.61.1.14x` broadband) — ninguna fuente real queda sin mitigar ni
mal enrutada a un adaptador que no le corresponde. Repetir el
escenario 5a después de este para confirmar que un ataque distribuido
de un solo dominio sigue clasificando como `DDOS_DISTRIBUTED` (sin
regresión).

---

## Limpieza final

```bash
curl -X POST localhost:5050/api/topology/stop
curl -X POST localhost:5050/api/controller/stop
```
Ctrl-C en la terminal de `webtool/app.py` (confirmar el mensaje
`[webtool] apagando -- deteniendo topologia y controlador...`).

## Tabla resumen de criterios de éxito

| Escenario | Verificación clave |
|---|---|
| 1 | 0 `DETECTION`, `active_attacks=[]`, tráfico real hacia `10.99.0.1` |
| 2a/2b/2c | `SYN_FLOOD` detectado y mitigado, dominio correcto, desbloqueo automático |
| 3a/3b/3c | ídem con `UDP_FLOOD` |
| 4a/4b/4c | ídem con `ICMP_FLOOD` (enterprise puede mostrar 2 detecciones, ida y vuelta) |
| 5a enterprise | ≤4 `SYN_FLOOD` individuales, NO `DDOS_DISTRIBUTED` (limitación estructural) |
| 5a mobile | `DDOS_DISTRIBUTED` con ≥5 fuentes, mitigación por UE |
| 5a broadband | `DDOS_DISTRIBUTED` con 8 fuentes (`attack_type=SYN_DISTRIBUTED`), switch_indices solo cosmético |
| 5b | una única `MULTIDOMAIN_DISTRIBUTED_ATTACK` contra `10.99.0.1`, mitigada correctamente por dominio real de cada fuente (no una detección por dominio, no todo por un solo adaptador) |
