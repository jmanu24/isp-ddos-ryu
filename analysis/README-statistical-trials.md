# Recolección estadística en el laboratorio distribuido

`analysis/run_vm_lab_trials.py` ejecuta las pruebas de forma secuencial contra
el laboratorio de VMs real (`deploy/vm-lab`) y genera una tabla `Td`, `Tm` y
`Tr` para Enterprise, Broadband, Mobile y Peering.

**Esto es distinto de `run_basic_matrix.py`** (la matriz de "24 combinaciones
básicas" -- 4 dominios × 3 vectores × DoS/DDoS -- que corre contra el
laboratorio Mininet, no contra `deploy/vm-lab`). Comparten la idea de
"4 dominios × 3 vectores", pero son dos suites distintas: `run_basic_matrix.py`
distingue explícitamente DoS (una fuente) de DDoS (varias fuentes) como eje
propio; `run_vm_lab_trials.py` no tiene ese eje -- cada dominio ya ataca con
el número de fuentes que su propio diseño permite (ver más abajo), y el eje
que sí tiene aquí es **modo de escenario** (`--mode`) × **modo de detección**
(`--detection-mode`), no DoS/DDoS. No usar los resultados de uno para
responder preguntas pensadas para el otro.

- **Td (tiempo de detección):** inicio real del generador → primera línea
  `DETECTION: ATTACK_DETECTED` para ese dominio/destino en el log del
  controlador. Un tiempo **entre eventos registrados**, no una medición
  directa de cuándo el paquete llegó al controlador.
- **Tm (tiempo de orden de mitigación):** detección → primera línea
  `MITIGATION: ...` logueada. Marca cuándo el controlador **decidió y envió**
  la orden (p. ej. `BGP_FLOWSPEC_DISCARD` a exabgp), **no** cuándo esa regla
  quedó instalada y aplicando en el plano de datos -- ver el aviso de
  `peering_backend.py` en el propio log ("dataplane installation on r1 is NOT
  verified").
- **Tr (tiempo hasta liberación registrada):** mitigación → primera línea
  `UNBLOCK`/`UNTHROTTLE` logueada. Tampoco implica por sí solo que el tráfico
  legítimo ya haya vuelto a pasar -- ver `traffic_recovered` abajo.

Ninguno de los tres debe leerse como "tiempo de efecto real sobre el
tráfico" sin la comprobación adicional que seccion siguiente describe --
son tiempos entre eventos que el propio controlador registró en su log, y
el log es la única fuente para ellos.

## Qué NO miden Td/Tm/Tr por sí solos, y qué sí lo complementa

- **`observed_pps`** (columna en `trials_long.csv`): la tasa realmente
  alcanzada por el generador, medida con contadores `tx_packets` reales de
  `/proc/net/dev` en el origen del ataque (en el netns `ue1` para Mobile),
  antes y después de la ventana de ataque. Es una aproximación a nivel de
  contador de interfaz, no una captura de paquetes -- documentado así en
  `Lab.sample_tx_packets()`, no se debe citar como una medición de
  precisión de captura.
- **`traffic_recovered`** (columna en `trials_long.csv`): tras Tr, se envía
  tráfico real desde la MISMA fuente del ataque (ping real) y se registra si
  llegó. Esto es lo que efectivamente valida "recuperación del servicio" --
  Tr por sí solo únicamente certifica que el log mostró un
  `UNBLOCK`/`UNTHROTTLE`. `None` (no `False`) en Broadband: esa fuente no
  tiene una IP de origen estable para volver a sondear (cada sesión vive en
  un macvlan que el agente de suscriptor administra) -- su propia señal de
  recuperación es el chequeo de 8 sesiones IPoE activas de
  `wait_for_baseline()`, un mecanismo distinto, no una omisión.

Las pruebas TCP, UDP e ICMP usan exactamente un origen. La prueba
`MULTIDOMAIN_FLOOD` necesita por definición más de un dominio; utiliza
exactamente un origen por dominio y el mismo destino, protocolo y puerto.
Broadband siempre utiliza una sola sesión atacante; las otras siete sesiones
permanecen en baseline. **Mobile usa un UE representativo (`ue1`, emparejado
con `du`/`ran`=cu1)**, no los 5 UEs del dominio -- igual que Enterprise usa
solo `ent-site-1` (de 5) y Peering solo `peer-router` (su única fuente
posible). Los resultados de Mobile en esta campaña caracterizan la cadena
`ran(cu1)→du(du1)→ue1`, no el comportamiento agregado de los 5 UEs/DUs del
dominio.

## Modo de ESCENARIO: `--mode {isolated,multidomain,both}`

Qué ataque se lanza -- un dominio por corrida (`isolated`) o los dominios
seleccionados atacando a la vez (`multidomain`, vía `MULTIDOMAIN_FLOOD`).

- **`isolated`** (recomendado para la matriz básica de 4 dominios × 3 vectores):
  solo TCP/UDP/ICMP_FLOOD, un dominio por corrida. Si `MULTIDOMAIN_FLOOD` queda
  en `--vectors`, se descarta.
- **`multidomain`** (recomendado para el escenario de ataque coordinado):
  solo `MULTIDOMAIN_FLOOD`, exige `--domains` con al menos 2 dominios.
- **`both`** (default, comportamiento previo sin cambios): corre exactamente
  los `--vectors` indicados, mezclando ambos tipos en la misma campaña.

## Modo de DETECCIÓN: `--detection-mode {isolated,multidomain}`

Eje **independiente** del anterior -- qué tan correlacionado está el
controlador, no qué ataque se lanza. El mismo ataque (mismas fuentes, tasas,
duración, destino, umbrales) corre igual en ambos modos; lo único que cambia
es si `correlation.correlator.MultidomainCorrelator` fusiona telemetría entre
dominios antes de que `detection/engine.py` la vea:

- **`multidomain`** (default, comportamiento previo sin cambios): eventos de
  distintos dominios hacia el mismo destino se agrupan en un solo
  `CorrelatedEvent` -- esto es lo que habilita `MULTIDOMAIN_DISTRIBUTED_ATTACK`
  y la coordinación entre dominios que la propuesta plantea.
- **`isolated`**: cada dominio procesa únicamente su propia telemetría, sin
  correlación ni coordinación entre dominios -- la línea base necesaria para
  demostrar que la correlación aporta algo, no solo que cualquiera de las dos
  formas detecta el ataque.

Cambiar de modo reinicia `ryu-manager` (vía un drop-in systemd transitorio,
`Lab.set_detection_mode()`) **antes** de que arranque la campaña -- nunca a
mitad de una corrida. Para el contraste A/B real: correr la MISMA matriz dos
veces, una por cada `--detection-mode`, idealmente alternando/aleatorizando
cuál corre primero entre sesiones (ver "Trazabilidad" más abajo).

La validación de ambos modos (`--mode` y `--detection-mode`) es inmediata
(antes de tocar cualquier VM): una combinación imposible (p. ej. `--mode
multidomain` con un solo dominio) termina con error en el arranque, no a
mitad de la campaña con un "Skipping..." silencioso.

```bash
# Matriz básica, aislada en ataque Y en deteccion, los 4 dominios
python3 analysis/run_vm_lab_trials.py --mode isolated --detection-mode isolated \
  --iterations 30 --output-dir analysis/results/vm-lab-isolated-isolated-30

# Misma matriz, con correlación multidominio activada -- el contraste A/B
python3 analysis/run_vm_lab_trials.py --mode isolated --detection-mode multidomain \
  --iterations 30 --output-dir analysis/results/vm-lab-isolated-multidomain-30

# Escenario multidominio (ataque coordinado) con deteccion multidominio
python3 analysis/run_vm_lab_trials.py --mode multidomain --detection-mode multidomain \
  --iterations 30 --output-dir analysis/results/vm-lab-multidomain-multidomain-30
```

## Repetibilidad de Mobile: `--repeatability-cycles N`

Una corrida exitosa de Mobile demuestra que la cadena `ran(cu1)→du(du1)→ue1`
**funciona**; no demuestra que sea **estable**. `--repeatability-cycles N`
(requiere `--domains mobile` exactamente) hace lo siguiente:

1. Valida la cadena una vez (conexión, tráfico, detección, mitigación,
   liberación, recuperación -- un ciclo completo).
2. Repite el ciclo completo `N` veces seguidas, verificando antes de CADA
   ciclo si la cadena ya estaba sana por sí sola o si necesitó una
   recuperación automatizada (`reconnect_mobile_domain.yml --tags
   cu1,du1,ue1`) para volver a estarlo.
3. Reporta un resumen: cuántos ciclos terminaron OK, cuántos confirmaron
   `traffic_recovered`, y cuántos necesitaron intervención entre ciclos --
   esta última cifra es la métrica de estabilidad real; su objetivo es 0.

```bash
python3 analysis/run_vm_lab_trials.py --repeatability-cycles 20 \
  --domains mobile \
  --output-dir analysis/results/vm-lab-mobile-repeatability-20
```

## Manejo de fallos de Mobile

Antes de CADA corrida que incluya Mobile (no solo al arrancar la campaña) se
comprueba la cadena `ran(cu1)→du(du1)→ue1` (señales de E2/F1/RRC/ping real,
igual que `deploy/vm-lab/webtool/status_checks.py`). Si está mal, se intenta
UNA recuperación automatizada acotada (`reconnect_mobile_domain.yml --tags
cu1,du1,ue1`, `power_cycle=false`); cualquier excepción de esa recuperación
se captura (nunca tumba la campaña completa) y se convierte en el motivo de
invalidación de la corrida:

- **Corrida aislada** (Mobile es el único dominio de esa corrida): si la
  cadena no se recupera, SOLO esa fila queda `status=INVALID` y su ataque
  nunca se lanza -- las corridas de los otros dominios en esa misma
  iteración/vector siguen su curso normal, sin verse afectadas.
- **Escenario conjunto** (`MULTIDOMAIN_FLOOD` con Mobile entre los
  atacantes): si la cadena de Mobile no se recupera, TODAS las filas de ese
  escenario quedan `status=INVALID_SCENARIO` y NINGÚN dominio llega a lanzar
  su ataque -- un ataque de 3 de 4 dominios no es el evento coordinado de 4
  dominios que ese escenario mide, así que nunca debe contarse como tal.

Ni `INVALID` ni `INVALID_SCENARIO` detienen la campaña (a diferencia de un
`ERROR`/`INCOMPLETE` real en un dominio que no es Mobile) -- se imprimen como
advertencia y la campaña sigue con el siguiente trabajo. Ambos quedan fuera
del conjunto de corridas ya completadas, así que `--resume` los vuelve a
intentar como cualquier combinación todavía no resuelta.

El healthcheck de arranque (y el que corre antes de cada corrida) solo
revisa las VMs/servicios de los dominios que `--domains` realmente
seleccionó -- una campaña sin `mobile` nunca queda bloqueada, ni
ralentizada, por la inestabilidad conocida de ese dominio.

## `NO_DETECTION`: ausencia de detección como resultado válido

Si el ataque se confirma realmente lanzado (`observed_pps > 0`, medido por
`Lab.sample_tx_packets()`) pero nunca aparece una línea `ATTACK_DETECTED`
dentro de `--event-timeout`, la fila queda `status=NO_DETECTION` -- un
resultado experimental válido para una comparación de sensibilidad A/B
(`--detection-mode isolated` vs. `multidomain`), no una falla del script.
`NO_DETECTION`, igual que `INVALID`/`INVALID_SCENARIO`, no detiene la
campaña y sí cuenta como corrida completada para `--resume`. Una detección
que SÍ ocurrió pero cuya mitigación/recuperación nunca llegó sigue siendo
`INCOMPLETE` (síntoma de un bug real del pipeline, como el de FLOWSPEC de
peering encontrado en esta misma campaña) y sigue deteniendo la campaña.

`MULTIDOMAIN_FLOOD` lanza ahora el ataque de enterprise desde los 5 hosts
`ent-site-1..5` (no solo uno) -- un solo atacante por dominio nunca puede
cruzar `config.settings.DIST_MIN_SOURCES` (5), así que antes este escenario
no podía demostrar `MULTIDOMAIN_DISTRIBUTED_ATTACK` bajo ninguna selección
de `--domains` (máximo 4 dominios = 4 fuentes). Con enterprise participando,
la campaña sí puede alcanzar el umbral por sí sola.

## Manifiesto de campaña (`--resume`)

Cada `--output-dir` guarda un `campaign_manifest.json` con la condición
experimental (`--domains`, `--vectors` efectivos, `--mode`,
`--detection-mode`, `--attack-duration`, `--event-timeout`,
`--repeatability-cycles`). `--resume` contra un directorio cuyo manifiesto
no coincide con la invocación actual falla rápido en vez de mezclar
condiciones distintas (p. ej. `isolated` y `multidomain`) en el mismo
`trials_long.csv`/`trials_table.csv` sin forma de distinguir después cuál
fila vino de cuál. Usar un `--output-dir` separado por condición.

## Trazabilidad por corrida

Cada fila de `trials_long.csv` incluye, además de dominio/vector/corrida:

- `code_version`: `<hash runner>+controller=<hash orchestrator>` -- el
  checkout que generó la corrida Y el checkout realmente desplegado en
  `orchestrator` (`/opt/Tesis_Controller`), que pueden diferir entre sí
  (+ sufijo `-dirty` en cualquiera de los dos si había cambios sin
  commitear).
- `detection_mode` / `scenario_mode`: los dos ejes A/B de esta corrida.
- `observed_pps`, `traffic_recovered`: ver la sección de arriba.
- `status`/`error`: incluye `INVALID`/`INVALID_SCENARIO`/`NO_DETECTION`
  además de `OK`/`INCOMPLETE`/`ERROR`/`DRY_RUN` -- las corridas fallidas y
  las inválidas se conservan en `trials.jsonl`, nunca se descartan.

Una corrida cuyos eventos de log se completaron (`status=OK`) pero cuya
sonda de recuperación post-mitigación falló (`traffic_recovered=False`,
contra el servicio TCP real que la víctima expone -- no un ping ICMP) NO
cuenta como terminada para `--resume`: se reintenta como cualquier otra
combinación sin resolver.

Para una comparación A/B honesta entre campañas (`--detection-mode isolated`
vs. `multidomain`, o entre sesiones de distintos días), alternar o
aleatorizar cuál corre primero entre sesiones, no correr siempre la misma
primero -- un efecto de orden (caché, estado residual, hora del día) puede
confundirse con el efecto del modo si una condición siempre corre primero.

## Tamaño de muestra

El valor por defecto es **30 corridas independientes por combinación**, un
punto de partida razonable para una campaña piloto -- no una garantía de
suficiencia estadística por sí sola. Usar una campaña piloto corta (p. ej.
`--iterations 10`) para estimar la variabilidad real (dispersión de Td/Tm/Tr)
antes de comprometerse a un tamaño de muestra final; si la dispersión es alta,
ampliar (`--resume --iterations 50` o más) en vez de asumir que 30 ya alcanza.

## Ejecución

Ejecutar desde la raíz del repositorio en el jump host:

```bash
python3 analysis/run_vm_lab_trials.py --iterations 30 \
  --output-dir analysis/results/vm-lab-30
```

Desde un worktree, el script usa automáticamente el inventario generado en el
checkout principal (`~/isp-ddos-ryu`). También puede indicarse explícitamente
con `--inventory /ruta/absoluta/inventory.ini`.

La ejecución completa puede tardar varias horas porque cada corrida espera el
desbloqueo real y un periodo de enfriamiento. No deben lanzarse ataques
manuales mientras esté activa.

Para una validación corta del procedimiento:

```bash
python3 analysis/run_vm_lab_trials.py --iterations 2 \
  --domains enterprise broadband \
  --vectors TCP_SYN_FLOOD UDP_FLOOD \
  --output-dir /tmp/vm-lab-smoke
```

Si una corrida queda incompleta (`ERROR`/`INCOMPLETE` real, no
`INVALID`/`INVALID_SCENARIO`), el programa termina sin continuar con la
siguiente. Después de resolver la causa:

```bash
python3 analysis/run_vm_lab_trials.py --iterations 30 \
  --output-dir analysis/results/vm-lab-30 --resume
```

Archivos generados:

- `trials.jsonl`: checkpoint append-only con trazabilidad completa.
- `trials_long.csv`: una fila por dominio, vector y corrida.
- `trials_table.csv`: tabla ancha lista para el análisis estadístico.

El orden de las combinaciones se aleatoriza de forma reproducible para
reducir el sesgo por deriva temporal. Antes de cada corrida se comprueban
los servicios y se detienen generadores residuales; Broadband exige ocho
sesiones IPoE activas. Una prueba no se considera válida hasta observar
detección, mitigación y recuperación (y, cuando aplica, `traffic_recovered`).
