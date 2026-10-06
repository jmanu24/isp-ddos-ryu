# Baseline: restauración explícita de presupuestos UE

El preflight obtiene IMSI por IP de las UE configuradas desde la telemetría real del core y exige KPM recientes asociados a esas identidades. Envía una orden unblock para cada identidad, aunque el registro enforced del actuador esté vacío. Valida HTTP 202 accepted=true y, después, un registro por IMSI con action=unblock, max_prb=100, etiqueta única BENIGN_BASELINE:<run_id>:<nonce> y timestamp reciente (tolerancia de reloj de 1 s). Los registros históricos no sirven como confirmación; las entradas adicionales no sustituyen a las UE esperadas.

Cada run exporta baseline_control.preflight.mobile con las identidades, IP, aceptaciones, registros recientes y hash de la implementación del preflight. La confirmación disponible es el estado del actuador después de procesar/despachar la orden. ran_ack_verified=false declara expresamente que no hay acuse RAN por UE ni lectura física de cuota en este contrato. No se debe describir el registro local como un readback del scheduler.

La preparación falla antes del tráfico si faltan identidades, KPM recientes, aceptación o registros nuevos. Los cambios no reinician radio, core ni UE; restauran únicamente el presupuesto mediante el mecanismo RC existente. Los perfiles BENIGN_V1, semillas, planes, ground truth de 5 s y plan_hash se conservan.
