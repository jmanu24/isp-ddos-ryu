# Falsos positivos y calibración de umbrales

## Escenarios y medidas

B0 con pipeline baseline mide entrega benignamente sin detección/mitigación. B0 con pipeline enabled permite medir falsas alarmas y decisiones de mitigación sobre el mismo tráfico benigno. El déficit de payload no es una tasa de falsos positivos.

La unidad de evaluación es dominio × ventana de 5 s. Solo se incluyen ventanas completas, BENIGN, fuera de warmup y con un ciclo activo que observó telemetría reciente de fuentes o destinos del experimento. Una ventana sin ciclo, con captura interrumpida o con fuentes no atribuibles permanece UNKNOWN/excluida: no se cuenta como TN. FPR = FP / (FP + TN). Detección y decisión ponderada tienen contadores y tasas separados. No se computan tasas retroactivas a partir de silencio en logs antiguos.

La atribución usa IPs del mapeo de ejecución, evidencias de agentes y direcciones observadas en los namespaces. Las detecciones sin fuente atribuible se reportan separadamente. Las IP son identidades de laboratorio, no una prueba de identidad externa. Las ventanas BENIGN presuponen que no hubo ataques externos no registrados.

## Evidencia capturada

El controlador emite LAB_AUDIT JSON (schema 1): cycle, detection, decision, mitigation_attempt, mitigation_issued y mitigation_release. Incluye timestamps Unix, UUID, fuentes/destinos, dominio, tipo, PPS, BPS (bytes/s), score observado/umbral, confidence, pesos, score efectivo, umbral de decisión y resultado de despacho. Cada ciclo registra las fuentes observadas, restricciones internas reportadas, umbrales y hashes del código efectivamente instalado.

Un flujo SSH persistente y autenticado recoge estos registros del orquestador. Los errores de captura se marcan como gaps. La IP de cada interfaz/namespace se muestrea mediante los colectores existentes, sin abrir una sesión SSH por evento.

mitigation_issued significa que el backend de despacho devolvió éxito; no confirma por sí solo que el plano de datos bloqueó paquetes. Los segundos de restricción provienen de muestras del estado interno en ventanas de 5 s, no de tiempos exactos de aplicación. Las retiradas/cambios de IP se correlacionan con acciones de los 30 s anteriores, como asociación temporal, sin afirmar causalidad.

## Dashboard y exportación

En la ejecución aparece Falsos positivos e impacto: ventanas elegibles, FP y tasa de detección, FP y tasa de decisión, ventanas con acciones, restricción reportada, payload y errores de IP por dominio. Cambios de IP muestra direcciones anteriores/nuevas y acciones cercanas.

Cada nueva exportación incluye detection_events.jsonl, detection_evaluation.json, detection_windows.csv, fixed_ip_changes.json, threshold_snapshot.json y audit_capture_status.json. Los archivos BENIGN_V1, plan_hash, ground truth y perfiles de ejecución existentes se conservan.

## Calibración

Seleccionar pruebas B0 reales, completadas y con pipeline activo. Usar semillas diferentes entre entrenamiento y validación; no repetir un run en ambas selecciones. Comparar una lista de umbrales de decisión. El candidato se elige con entrenamiento solamente: el menor de la lista cuya FPR de decisión observada sea ≤1 % en cada dominio, con al menos 200 ventanas benignas evaluadas en total y 20 por dominio. Solo ese candidato se consulta en validación. No usar después esas semillas de validación para retocar el umbral.

El replay aplica score × confidence × peso al conjunto de candidatos registrado. No vuelve a ejecutar el detector ni simula el efecto contrafactual sobre tráfico/red. Los datos registrados con mitigación están afectados por la intervención: hacen falta nuevas pruebas reales para confirmar la calibración. Benignos permiten estimar falsas alarmas; ataques independientes son necesarios para validar sensibilidad. El candidato es una propuesta y no se aplica automáticamente.

Leer umbrales consulta los valores vigentes del orquestador. Aplicar admite DECISION_THRESHOLD, SYN_THRESHOLD, UDP_THRESHOLD, ICMP_THRESHOLD y DIST_PPS_THRESHOLD, valores finitos positivos. Requiere que el hash de configuración coincida y no haya experimentos ni lease baseline activos. Cambiar umbrales reinicia ryu-manager; la configuración anterior se guarda privadamente y se restaura si el servicio no vuelve. El inicio de experimentos y el cambio de umbrales comparten un lock para evitar carreras. Cambiar los umbrales del detector requiere nuevas pruebas: el replay de decisión no los recalcula.

## Despliegue y límites

El módulo core/experiment_audit.py es de observación y se habilita mediante LAB_AUDIT_ENABLED=true en ryu-manager. tools/install_audit_hooks.py agrega únicamente hooks a la versión instalada, sin reemplazar diferencias locales de la lógica. El colector se habilita con detection_audit.enabled=true en lab.connected.yaml. Actualizar también /opt/benign-lab/interface_probe.py en nodos monitoreados para obtener direcciones IPv4.

Los relojes deben estar sincronizados. La telemetría, el muestreo de IP y las acciones pueden tener distinta resolución; los timestamps no prueban causalidad. El historial central mantiene seis horas; la exportación de cada experimento conserva su evidencia. La captura y logging agregan carga: registrar esta revisión de instrumentación al comparar campañas anteriores y nuevas.

## Probes de UE/UE2 con disco lleno

En este despliegue ambas raíces de 40 GiB estaban al 100 %. Los probes se instalaron en /run/benign-lab (tmpfs), con un lanzador pequeño en la ruta anterior. Los nodos ue/ue2 tienen bootstrap_probe=true: cada reconexión del colector reinstala desde el control el probe y resource_probe.py en RAM, también después de un reboot. No se borraron logs. Esta solución mantiene el monitoreo, pero no resuelve el disco lleno: liberar/archivar datos o ampliar correctamente el filesystem sigue pendiente antes de campañas extensas.

Se exige la misma configuración del detector y los mismos hashes de implementación entre entrenamiento y validación; el umbral global de decisión puede variar para estudiar su gate. La atribución de decisiones usa únicamente el candidato ganador de cada grupo, no todos sus candidatos.
