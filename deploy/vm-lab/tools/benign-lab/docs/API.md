# API

Mismo origen que el panel. Si se configuró token, enviar `Authorization: Bearer <BENIGN_API_TOKEN>`. Un solo experimento activo por controlador. Validaciones de entrada devuelven 400/422; recursos no existentes 404.

| Método | Ruta | Función |
|---|---|---|
| GET | `/api/config` | Mapeo y perfiles cargados |
| GET / POST | `/api/plans` | Listar / materializar |
| POST | `/api/plans/import` | JSON completo, validar hash, preservar archivo |
| GET | `/api/plans/{hash}` | Plan completo |
| GET | `/api/plans/{hash}/download` | Descargar benign_plan.json |
| POST | `/api/plans/{hash}/preflight` | Validar mapeo y mostrar agentes, sin conexión |
| GET / POST | `/api/runs` | Listar / iniciar |
| GET | `/api/runs/{id}` | Snapshot, contadores y logs recientes |
| GET | `/api/runs/{id}/stream` | SSE cada 500 ms, termina al finalizar |
| GET | `/api/runs/{id}/events` | Filtros domain/status, offset, limit≤500 |
| GET | `/api/runs/{id}/ground-truth` | Ventanas actuales |
| POST | `/api/runs/{id}/stop` | Cancelar sin reanudar |
| POST | `/api/runs/{id}/attack` | Registrar inicio/fin de ataque externo |
| GET | `/api/runs/{id}/export` | ZIP con plan, CSV, manifiesto y logs |

Materialización:

```json
{"seed":3,"duration_s":600,"capacity_mbps":{"mobile":100,"fixed":100,"enterprise":100,"peering":100}}
```

Ejecución real B0:

```json
{"plan_hash":"<64 hex>","mode":"lab","scenario":"B0","speed":1,"attack_windows":[]}
```

Demostración emparejada:

```json
{"plan_hash":"<el mismo hash>","mode":"simulation","scenario":"B0+attack","speed":20,"attack_windows":[{"name":"external_attack","start_s":300,"end_s":360}]}
```

Anotación a partir de la confirmación del generador externo, durante una ejecución B0+attack:

```json
{"name":"external_attack","action":"start"}
```

Usar `"action":"stop"` al finalizar. Se registra el instante relativo en que la API recibe la confirmación; no hay backdating. Para calibrar latencias de anotación, correlacionar también el log propio del generador externo. El modo no inicia un ataque. Las ventanas programadas sin anotación no se elevan a verdad observada.

La persistencia de ejecuciones usa JSON/JSONL/CSV locales; no habilitar varios workers ni múltiples controladores contra el mismo directorio de datos. Los perfiles y el mapeo sólo se editan en archivos, no mediante comandos arbitrarios enviados a la API.
