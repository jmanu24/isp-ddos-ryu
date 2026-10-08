# Etapas de ataques

Tres botones en Pruebas y programación preparan Monitor con un plan original de semilla 1, 2 o 3, classic y laboratorio. No inician pruebas ni generan ataques automáticamente.

1. B0 con pipeline enabled: medir falsos positivos.
2. B0+attack con pipeline baseline: suspender detección y mitigación con el mismo BaselineGuard existente; watchdog y restauración permanecen activos.
3. B0+attack con pipeline enabled: medir impacto y protección.

Los ataques siguen siendo externos. Configurar los mismos tipo, generador, tasa, destino y duración en etapas 2 y 3; marcar inicio y fin reales. Las ventanas previstas nunca se convierten automáticamente en ATTACK observado; permanecen UNKNOWN hasta su confirmación. El benign_plan.json y su plan_hash no se modifican. Las series automáticas siguen limitadas a B0 porque requieren operador para ataques.

El cambio habilita B0+attack sin pipeline en modo laboratorio exclusivamente. Benchmark conserva la restricción B0 sin ataque; no se admite baseline de simulación. No se cambian umbrales, VMs, capacidades ni scripts externos de ataque.
