# Capacidades del plan y referencia del laboratorio

Los campos del formulario definen las capacidades de referencia usadas para materializar las tasas y cuotas del plan. No modifican la calibración del laboratorio en lab.connected.yaml. Un plan válido puede usar capacidades distintas; el ejecutor respeta sus rate_bps, planned_bytes y deadlines, sin reescribir benign_plan.json.

Cada ejecución registra plan_capacity_mbps, lab_reference_capacity_mbps y capacities_differ, además de plan_hash, execution_hash y lab_hash. Las diferencias también aparecen en los logs. El archivo lab_snapshot.json conserva la configuración calibrada; el plan conserva las capacidades elegidas.

Para B0 y B0+ataque reutilizar exactamente el mismo archivo y conservar el perfil de ejecución y mapeo. Cambiar capacidades materializa otro plan y cambia su hash. BENIGN_V1 permanece intacto. Una capacidad mayor que la referencia puede exigir más carga; no aumenta la capacidad física ni garantiza cumplimiento.

Si una campaña requiere igualdad estricta, configurar require_matching_plan_capacities: true. Por defecto la referencia calibrada no impide un plan de carga personalizado. Se conservan las validaciones de mapeo, destinos, cuotas, reloj y suspensión/restauración del pipeline.
