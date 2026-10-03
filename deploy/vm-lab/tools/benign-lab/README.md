# DDOS PUCP LAB

## Instalación conectada en isp-ddos-ryu

Actualización del 1 de octubre: cinco sitios Enterprise encendidos y accesibles, diez sesiones Fixed activas, agentes y receptores desplegados, panel en el control node con Python 3.8 y workers con Python 3.10. Usar `config/lab.connected.yaml`. Consultar [operación actual](docs/CONNECTED_DEPLOYMENT.md) para acceso, credenciales externas y calibración pendiente.

## Adaptación al laboratorio real

Usar `config/lab.real.yaml` como inventario explícito, completar los campos pendientes y seguir [despliegue real](docs/REAL_LAB_DEPLOYMENT.md). Incluye Mobile por namespaces UE, Fixed por sesiones IPoE existentes (namespace o IP enlazada), Enterprise por sitios y Peering agregado con gateway comprobado. `benign-lab inspect-mapping` identifica parámetros faltantes. El panel muestra métricas por dominio y evidencia de rutas. No se ha verificado conexión con las VMs reales; consultar [resumen y validación](docs/INTEGRATION_REPORT.md).

Herramienta ejecutable para materializar, orquestar y observar `BENIGN_V1`. Backend Python/FastAPI; frontend HTML/CSS/JavaScript servido por el mismo proceso, sin Node, servicios externos ni CDN. Agentes Python sin dependencias para Linux/VMs/namespaces y receptor TCP/UDP/HTTP incluido.

## Inicio rápido

Python **3.8 o superior**. Para namespaces: Linux con `iproute2`; para SSH: OpenSSH, y sshpass cuando se use autenticación por contraseña. El modo demostración también funciona en macOS.

```bash
cd benign-lab
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock
pip install --no-deps --no-build-isolation -e .
benign-lab serve
```

Si el entorno no tiene `setuptools`, usar `pip install -e '.[test]'` como alternativa (resuelve versiones dentro de los rangos de `pyproject.toml`). Abrir **http://127.0.0.1:8765**. Mantener **un solo proceso/worker** del servidor: este coordina el estado y los agentes.

1. Materializar un plan con semilla 1 y 600 s. La configuración inicial es `config/lab.demo.yaml`; las capacidades de esta demo son valores de ejemplo.
2. Elegir **Demostración**, B0 y velocidad 20×. Se ejecuta en unos 30 s sin generar tráfico de red.
3. Revisar carga planificada, eventos, logs y ground truth. Descargar el JSON y el ZIP de resultados.
4. Seleccionar el **mismo plan guardado**, elegir B0+attack y ejecutar otra vez. El baseline se copia byte por byte.

Para tráfico real local, abrir otra terminal y ejecutar:

```bash
python -m benign_lab.agent receiver
```

En el panel elegir **Laboratorio**. La velocidad pasa a 1×. Este modo emite tráfico real a los destinos configurados. La demo mapea todos los clientes lógicos al mismo host, por lo que **no reproduce el aislamiento ni las rutas de las VMs**.

## Qué incluye

- YAML de Mobile (5 UE), Fixed (10 suscriptores lógicos), Enterprise (5 sitios) y Peering (20–60 flujos concurrentes, pool de 100 identidades).
- Semillas independientes derivadas de SHA-256 por dominio; ningún reloj entra en el plan.
- Sesiones web con objetos Pareto y pausas exponenciales, streaming con ciclos, flujos TCP/UDP, ICMP mediante ping, comunicaciones intersite y picos benignos.
- Normalización de tasas bulk y validación en **todos los límites temporales de eventos**, no sólo en muestras por segundo.
- Mezcla de peering por **bytes planificados**: TCP 68 %, UDP 28 %, ICMP 1 %, other 3 %.
- Plan inmutable con perfiles efectivos, capacidades, advertencias, resúmenes, `profile_hash` y `plan_hash` SHA-256.
- Agentes locales, `ip netns exec`, SSH y SSH+namespace; preparación previa, comprobación de relojes, inicio coordinado y cancelación.
- Monitoreo SSE, estados por evento, tiempos reales, desfase de inicio, bytes de aplicación TX/RX, chunks, puertos y respuestas ICMP.
- Artefactos persistentes, recuperación explícita como `interrupted` tras un reinicio, CSV y ZIP exportables.
- Ground truth de 5 s con warmup de 60 s excluido de evaluación y etiquetas diferenciadas para ventanas sin confirmar.

## Mapear el laboratorio real

Copiar `config/lab.example.yaml` a `config/lab.yaml`. La única dirección de destino proporcionada por la conversación es **victim = 10.55.0.100**. Las IP de gestión y de los sitios empresariales del ejemplo **son marcadores**, no direcciones descubiertas.

```bash
benign-lab serve --lab config/lab.yaml --data data
```

Guía detallada: [docs/LAB_MAPPING.md](docs/LAB_MAPPING.md). No se crean VMs, sesiones IPoE, rutas, túneles 5G ni bridges: el laboratorio debe proporcionarlos. No se ha conectado este proyecto a las 23 VMs durante su construcción.

## B0 y B0+attack: protocolo de comparación

1. Materializar una vez y guardar el JSON.
2. Correr B0 con ese archivo.
3. Volver a seleccionar/importar ese archivo para B0+attack. **No regenerarlo**, aunque tenga la misma semilla.
4. Mantener capacidades y mapeo. Comparar `plan_hash`, `plan_file_sha256` y `lab_hash` de ambos `run.json`.
5. El controlador de ataques es externo. Este proyecto **no implementa ni lanza ataques**. Registrar el inicio y fin reales desde el panel o la API `/attack` cuando el generador externo los confirme.
6. Correlacionar `started_at` y los tiempos relativos con los contadores/PCAP/telemetría de Ryu, OVS y equipos.

Un baseline idéntico significa **las mismas instrucciones y presupuestos ofrecidos**. Los bytes efectivamente entregados, retransmisiones y tiempos pueden diferir durante el ataque; eso es parte del experimento. No se afirma identidad de PCAP.

## Generar/verificar por CLI

```bash
benign-lab generate-plan --seed 3 --duration 600 --lab config/lab.yaml --out plans/seed003/benign_plan.json
benign-lab validate-plan plans/seed003/benign_plan.json
```

El CLI rechaza sobrescribir un archivo con otro plan distinto. Para ejecutar uno generado por CLI, importarlo en el panel o mediante la API. Un plan contiene los perfiles utilizados: modificar los YAML sólo afecta a planes nuevos.

El `plan_hash` es SHA-256 del JSON canónico UTF-8, claves ordenadas, separadores `,`/`:`, sin `plan_hash`, sin espacios ni NaN. **No equivale al hash del archivo completo** (que incluye su propio hash). `plan_file_sha256` registra además el hash de los bytes exactos copiados a cada ejecución. La importación conserva los bytes del primer archivo guardado con ese `plan_hash`; una segunda representación con igual contenido reutiliza la copia existente.

## Resultados

```text
data/
  plans/<plan_hash>.json
  runs/<experiment_id>/
    benign_plan.json          # copia exacta del plan seleccionado
    lab_snapshot.json        # mapeo efectivo, sin claves privadas
    run.json                 # semilla, hashes, modo, escenario, reloj y estado
    event_states.json         # estado recuperable de cada evento
    generated_events.csv     # planificación + observación por evento
    ground_truth_windows.csv # etiquetas y cobertura por ventana
    logs.jsonl               # mensajes operativos
    events.jsonl             # transiciones reportadas por agentes en modo real
    metrics.jsonl            # muestras de payload durante ejecución
```

Los eventos pendientes/activos se guardan cada 5 s y al terminar; los eventos de agentes se anexan inmediatamente a `events.jsonl`. Una terminación abrupta puede dejar hasta 5 s de atraso en el snapshot. Tras reinicio, el controlador marca la ejecución como `interrupted`; **no reanuda automáticamente** un experimento temporal incompleto. Los agentes se detienen al cerrarse stdin/SSH y también tienen un límite de tiempo local.

## Ground truth

Ventanas semiabiertas `[inicio, fin)`, con una última ventana parcial si la duración no es múltiplo de 5. Un ataque que termina en 360 no etiqueta `[360,365)`.

- `planned_label`: calendario previsto para B0+attack.
- `label`: `BENIGN` / `ATTACK` / `UNKNOWN` (IDs 0 / 1 / -1).
- `annotation_source`: baseline, calendario sin confirmar o registro externo del operador.
- `observed_complete`: la ventana terminó antes del fin de la observación disponible.
- `evaluation`: ventana observada completa y situada después del warmup.

Las ventanas futuras o previstas para ataque sin registro se marcan `UNKNOWN`. Una anotación de ataque etiqueta cualquier ventana solapada, incluso parcialmente; usar `observed_complete` para excluir observaciones truncadas. Una ventana BENIGN no significa que todos los generadores cumplieron su presupuesto: revisar el estado de la ejecución y los eventos para controlar calidad experimental. Las anotaciones son declaraciones del operador/controlador externo, no detecciones de paquetes de ataque.

## Modelo y límites de fidelidad

Ver [docs/METHODOLOGY.md](docs/METHODOLOGY.md) antes de utilizar resultados en la tesis. Se destacan estas decisiones:

- La mezcla original puede resultar demasiado dispersa para alcanzar la media Enterprise sin exceder máximos. `common.yaml` agrega la opción explícita `normalization.supplement_bulk_when_sparse`. Si está habilitada, materializa eventos **`calibration_bulk`** adicionales y los declara en las advertencias. Deshabilitarla para preservar el modelo sin suplemento; en ese caso las medias inalcanzables se reportan. Esta extensión requiere evaluación metodológica al calibrar el laboratorio.
- HTTP es HTTP real **sin TLS**. Los perfiles denominados SSH/correo representan sesiones TCP sintéticas. DNS es UDP sintético. Streaming reproduce tasas y ciclos, no códecs. No se implementa QUIC.
- `other` es una categoría lógica representada explícitamente mediante **UDP** (`wire_protocol=udp`). La mezcla de protocolos IP en la red será, por tanto, UDP ≈31 %, no 28 %. No presentar esa aproximación como reproducción exacta de MAWI.
- Las tasas/volúmenes son payload de aplicación, excluyen cabeceras y tráfico de control. Los chunks TCP no son paquetes de red; UDP TX indica envío aceptado por el socket, no entrega confirmada.
- ICMP usa `ping`: produce solicitudes y respuestas, requiere permisos según el host y tiene intervalo mínimo operativo de 20 ms. Su tasa planificada puede no alcanzarse; el agente reporta respuestas/payload RX, no inventa TX. Capturar contadores de red para medir tráfico ICMP real.
- El generador es de carga moderada, con pacing de software. No es un generador de línea ni un sistema de tiempo real. Los resultados medidos deben contrastarse con las tasas planificadas antes de una campaña.

## Acceso desde otro equipo

La configuración predeterminada escucha sólo en localhost. Preferible un túnel SSH:

```bash
ssh -L 8765:127.0.0.1:8765 lab@CONTROLADOR
```

Para escuchar en la interfaz del laboratorio:

```bash
export BENIGN_API_TOKEN='un-token-largo-y-aleatorio'
export BENIGN_ALLOWED_HOSTS='localhost,127.0.0.1,10.10.0.5'
benign-lab serve --host 0.0.0.0 --lab config/lab.yaml
```

Introducir el token en **Configurar acceso**. Para redes no confiables, terminar HTTPS en un proxy o usar el túnel SSH: el servidor incorporado no configura TLS. No habilitar múltiples workers ni recarga automática durante un experimento.

## Pruebas y API

Resultado de esta entrega: **13 pruebas aprobadas**; detalles en [docs/VALIDATION.md](docs/VALIDATION.md). Se incluye un plan completo ya materializado en `examples/benign_plan.json`.

```bash
pytest -q
```

Pruebas de determinismo, independencia por dominio, integridad, límites exactos, mezcla volumétrica, ventanas, pares B0/B0+attack, exportación, detención, autenticación, adaptadores y tráfico real TCP/UDP/HTTP sobre loopback. Los adaptadores Linux/SSH requieren la validación adicional en el laboratorio.

[docs/API.md](docs/API.md) documenta los endpoints. El esquema OpenAPI se sirve en `/docs`.

Implementación apoyada en la documentación oficial de [FastAPI lifespan](https://fastapi.tiangolo.com/advanced/events/), [archivos estáticos](https://fastapi.tiangolo.com/tutorial/static-files/) y [subprocesos asyncio](https://docs.python.org/3/library/asyncio-subprocess.html).

## CPU de hosts

Vista CPU de hosts para ESXi y Windows, historial persistente de 6 horas y host_metrics.jsonl en las nuevas exportaciones. Configuración y escalas: [docs/HOST_CPU_MONITOR.md](docs/HOST_CPU_MONITOR.md).

## Recursos por VM y proceso

Monitoreo continuo de CPU, memoria, disco y procesos de los invitados Linux, con CPU Ready de ESXi y exportación vm_resources.jsonl. [Configuración, escalas y despliegue](docs/VM_RESOURCE_MONITOR.md).


La ejecución optimizada ofrece supervisores por VM, métricas agrupadas y un perfil TCP/HTTP persistente seleccionable. Consulta [OPTIMIZED_EXECUTION.md](docs/OPTIMIZED_EXECUTION.md) para despliegue y comparaciones reproducibles.

Las capacidades de un plan pueden diferir de la referencia calibrada. Consulta [PLAN_CAPACITIES.md](docs/PLAN_CAPACITIES.md) para registro y comparación de planes personalizados.
