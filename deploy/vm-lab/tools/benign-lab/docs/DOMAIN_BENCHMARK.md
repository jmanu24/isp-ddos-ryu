# Benchmark por dominio

En Plan benigno, Tipo de prueba permite elegir todos los dominios (baseline) o Benchmark Mobile, Fixed, Enterprise o Peering. Ajustar semilla, duración y capacidades, materializar el plan, comprobar el dominio y comenzar en modo Laboratorio. La ejecución real obliga B0 y suspende detección/mitigación mediante el guard existente; al finalizar restaura el pipeline. Simulación muestra valores sintéticos y no mide capacidad física.

Sólo se generan eventos del dominio seleccionado. Mobile utiliza sus cinco UE, Fixed sus diez namespaces, Enterprise sus cinco sitios y Peering su generador agregado actual. Los receptores, rutas y recursos compartidos siguen presentes; no se apagan VMs ni se suprime tráfico de fondo. El guard exige presupuestos UE sólo para Mobile y concesiones BNG sólo para Fixed, conservando las comprobaciones comunes del controlador y las restricciones del datapath.

BENIGN_V1 permanece intacto. El benchmark deriva un plan nuevo con purpose=domain_benchmark, benchmark_domain y parent_plan_hash; conserva exactamente los eventos de ese dominio del plan completo y tiene otro plan_hash. Los planes anteriores no se modifican. No se permite mezclar dominios en una importación marcada benchmark ni añadir ataques a esa ejecución.

El dashboard presenta porcentaje de cuota, Mbps medios previstos/observados y eventos fallidos. La exportación incluye benchmark_summary.json, plan, logs, ground truth de 5 s y métricas de interfaces/VMs/hosts. El volumen es payload reportado por los agentes y no certifica toda recepción UDP. Un benchmark interrumpido no equivale a completar la duración prevista.

Cada ejecución caracteriza el nivel de carga elegido, no descubre automáticamente la capacidad máxima. Para construir una curva, repetir con la misma semilla y duración en varios niveles de capacidad de referencia del plan; registrar cuotas, caudal, CPU Ready y estabilidad. Conservar los planes y hashes de cada nivel. No iniciar niveles simultáneamente. Validar después un baseline conjunto: las capacidades aisladas no garantizan que todos los dominios alcancen esos valores al mismo tiempo.
