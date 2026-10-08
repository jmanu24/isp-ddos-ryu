# Selector y serie estadística

Un selector elige benign_off, benign_on, attack_off o attack_on. Otro botón inicia 18 pruebas, seis por semilla original, classic y pausa 60 s. El orden está intercalado y cada copia conserva bytes/hash. La selección es independiente de Monitor.

Benignas: ejecución automática serial, pipeline suspendido o activo según selección. Ataques: externos/manuales, requieren origen IP y condiciones repetibles. El operador marca inicio/fin reales; tras cada prueba confirmada la serie espera continuar. Sin confirmación se detiene para revisión. No se generan ataques automáticamente.

La matriz global de ventanas 5 s calcula VP/VN/FP/FN únicamente con pipeline activo, fuera del warmup y con cobertura de todos los dominios. Las ventanas con ataque además requieren origen declarado observado; las ventanas previstas sin confirmación son UNKNOWN. Ataques positivos se atribuyen al origen declarado. Benigno sin pipeline y ataque sin mitigación sirven para medir impacto, no para fingir aciertos del clasificador.

No se modifican configuración de VMs, tasas, umbrales ni los planes. No se inicia ninguna serie durante el despliegue. No es una matriz por paquete ni implica verificación independiente de bloqueo.
