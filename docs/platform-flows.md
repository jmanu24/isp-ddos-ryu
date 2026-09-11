# Arquitectura y flujos de Tesis_Controller

Diagrama del código del repositorio después de retirar el simulador móvil/O-RAN.
Las líneas continuas representan conexiones implementadas; las discontinuas,
integraciones pendientes. Una conexión implementada no implica que su servicio
externo esté desplegado o validado en el testbed.

## 1. Vista general

```mermaid
flowchart TB
    subgraph inputs[Fuentes y redes]
        SW[Switches OpenFlow / OVS]
        BNG[BNGBlaster / Broadband]
        UPF[UPF: tráfico IP antes de NAT]
        CORE[Open5GS: abonados y sesiones PDU]
        RAN[srsRAN: contextos NGAP / F1AP / E1AP]
        RIC[Near-RT RIC + xApp + Gateway KPM]
    end
    subgraph ingestion[Adquisición y normalización]
        OF[OpenFlowAdapter + colectores]
        BA[BroadbandAdapter]
        EXP[Exportadores móviles reales pendientes]
        SNAP[Snapshot JSON atómico\ntesis.mobile.observations/v1]
        MA[MobileNetworkAdapter\nvalidación + deduplicación]
        CTX[MobileContext\nasociaciones temporales + contexto KPM]
        EV[TelemetryEvent\nIP origen / destino, tasas y metadatos]
        BGP[BGPPeeringAdapter\ncollect devuelve lista vacía]
    end
    subgraph pipeline[Ciclo del controlador Ryu]
        COR[MultidomainCorrelator\nagrupa por destino y suma tasas]
        DET[DetectionEngine\nfirmas de ataque y análisis multidominio]
        ORC[OrchestrationController]
        DEC[DecisionEngine\nevaluación de detecciones]
        ACT[MitigationAction\nselección por dominio y origen]
    end
    SW -->|PacketIn / FlowStats / PortStats| OF
    BNG -->|telemetría del pipeline BNG| BA
    UPF -.-> EXP
    CORE -.-> EXP
    RAN -.-> EXP
    RIC -.-> EXP
    EXP -.-> SNAP
    SNAP --> MA --> CTX --> EV
    OF --> EV
    BA --> EV
    BGP -->|sin eventos actualmente| EV
    EV --> COR --> DET --> ORC --> DEC --> ACT
    ACT --> OFM[OpenFlowMitigator\nreglas de bloqueo / liberación]
    OFM --> SW
    ACT --> BCM[Adaptador Broadband\ncontrol de sesiones]
    BCM --> BNG
    ACT --> MCM[Adaptador móvil\ncontrol no implementado: False]
    MCM -.-> RC[Backend E2SM-RC pendiente]
    RC -.-> RIC
    ORC --> OBS[Estado web, logs y métricas]
    DET --> OBS
    EV --> OBS
    OBS --> UI[Dashboard / Grafana / vista de bloqueos]
```

El controlador ejecuta la adquisición periódica en `_run_pipeline`. Los eventos
OpenFlow también nacen de las respuestas y notificaciones de los switches.
La detección low-and-slow usa además información de conexiones del adaptador
OpenFlow; no depende únicamente de la suma de volumen por destino.

## 2. Flujo móvil y atribución por UE

```mermaid
flowchart TD
    FILE[MOBILE_OBSERVATIONS_PATH] --> SCHEMA{Schema y timestamp válidos?}
    SCHEMA -->|no| DROP[Rechazar snapshot\nis_connected = False]
    SCHEMA -->|sí| LOAD[Cargar flows, bindings y kpms]
    LOAD --> DUP{Observación nueva y reciente?}
    DUP -->|no| SKIP[Omitir flujo]
    DUP -->|sí| VALID[Validar IPs, puertos, intervalo y contadores]
    VALID --> MATCH{Una sola asociación cubre\nnetwork_id, IP y todo el intervalo?}
    MATCH -->|sí| ID[Identidad resuelta\nSUPI + sesión + contexto RAN disponible]
    MATCH -->|no| UNK[Identidad unresolved\nconservar flujo IP]
    ID --> KPM[Filtrar KPM por fuente, nodo,\ncalidad, frescura y alcance]
    KPM --> SCOPE{Alcance del KPM}
    SCOPE -->|nodo| NODE[Contexto del nodo\nno atribuirlo íntegro a la UE]
    SCOPE -->|celda| CELL[Exigir cell_id coincidente]
    SCOPE -->|UE| UE[Exigir tipo y valor UEID coincidentes]
    NODE --> OUT[TelemetryEvent móvil]
    CELL --> OUT
    UE --> OUT
    UNK --> OUT
    OUT --> RATE[pps = paquetes / segundos\nbps = bytes / segundos]
    RATE --> PIPE[Correlación y detección existentes]
```

- Los contadores deben ser incrementos de un intervalo, no acumulados.
- KPM se adjunta en `flags.kpm_context`; no genera otro flujo ni suma volumen.
- `flags.ue_session` conserva la identidad resuelta. Los modelos de detección y
  las vistas todavía no exponen todos estos campos como entidades dedicadas.
- El estado conectado indica que el snapshot pasó la validación, no que se haya
  verificado la salud de Open5GS, del gNB o del RIC.
- Un flujo sin identidad inequívoca puede detectarse por IP; no habilita atribución
  ni mitigación individual de UE.
- El productor debe evitar duplicados entre puntos de observación. El correlador
  global aún suma todos los eventos: observar el mismo tráfico en UPF y OVS puede
  duplicar el volumen si ambos se habilitan sin una política de propiedad.

## 3. Operación de la webtool

```mermaid
sequenceDiagram
    actor Usuario
    participant UI as Webtool Flask
    participant W as Webtool Orchestrator
    participant LAB as Mininet / BNGBlaster
    participant R as Controlador Ryu
    participant O as OrchestrationController
    participant V as Estado web / métricas
    Usuario->>UI: Iniciar controlador y laboratorio
    UI->>W: Solicitud de arranque
    W->>R: Arrancar o adoptar controlador
    W->>LAB: Topología Enterprise/Broadband y baseline
    Usuario->>UI: Seleccionar escenario disponible
    UI->>W: Iniciar ataque de laboratorio
    W->>LAB: Enterprise o Broadband
    loop Ciclo de adquisición
        LAB->>R: Tráfico y estadísticas
        R->>R: Collect, correlación y detección
        R->>O: Detecciones
        O->>O: Decidir acción y gestionar estado
        O->>LAB: Despachar mitigación del dominio
        R->>V: Tasas, detecciones y logs
        O->>V: Estado de bloqueos
    end
    Usuario->>UI: Consultar / solicitar desbloqueo
    UI->>O: Ruta de control de desbloqueo
    O->>LAB: Liberación según backend
    O->>V: Actualizar estado
```

La webtool ya no crea gNBs ni UEs móviles simuladas. La entrada móvil real se
configura por entorno en el controlador y no depende del arranque de Mininet.
El diagrama de secuencia representa interacciones lógicas; la API/estado web
actúa como intermediario entre la webtool y la orquestación del controlador.

## 4. Límite importante del control móvil

El adaptador móvil devuelve `False` al solicitar mitigación. Sin embargo, la
orquestación heredada todavía registra un bloqueo móvil y devuelve éxito sin
propagar ese resultado (`orchestration/controller.py`, `_dispatch`). Por tanto,
**un bloqueo mostrado en la interfaz no demuestra una acción aplicada en la RAN**.
Esta inconsistencia debe corregirse antes de validar mitigación móvil de extremo
a extremo. Las rutinas heredadas de desbloqueo móvil tampoco constituyen una
confirmación E2SM-RC.

## 5. Mapa del código

| Responsabilidad | Archivo |
|---|---|
| Eventos OpenFlow y ciclo principal | `controller/ryu_controller_2.py` |
| Contrato de eventos comunes | `core/models.py` |
| Flujos, KPM y asociaciones móviles | `core/mobile_models.py` |
| Entrada de snapshots móviles | `telemetry/mobile_adapter.py` |
| Unión temporal y contexto radio | `correlation/mobile_context.py` |
| Agregación multidominio | `correlation/correlator.py` |
| Detección | `detection/engine.py` |
| Decisión | `decision/engine.py` |
| Despacho, estado y desbloqueos | `orchestration/controller.py` |
| Aplicación OpenFlow | `mitigation/openflow_mitigator.py` |
| UI y laboratorio | `webtool/app.py`, `webtool/orchestrator.py` |
| Métricas y estado | `web/metrics.py`, `web/state.py` |

Contrato y pasos pendientes: [Integración móvil](mobile-integration.md).
