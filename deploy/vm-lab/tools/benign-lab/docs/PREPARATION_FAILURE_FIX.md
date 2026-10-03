# Corrección de abortos durante preparación (2026-10-02)

La captura `20261002T204437-48bae9da` terminó antes de iniciar tráfico: 21 agentes preparados, 9 comprobaciones de reloj registradas, 7 904 eventos sin ejecutar, `error` vacío. El último registro de reloj precede al error en 5,93 s. La evidencia es compatible con un TimeoutError de preparación; la captura antigua no contiene traceback y no permite identificar con certeza la llamada exacta.

Se corrigieron dos causas de fragilidad:

- Las sondas de reloj tenían un único tiempo de espera de 5 s y descartaban toda la preparación ante una demora transitoria. Ahora se intentan hasta cinco sondas, se ignoran respuestas tardías de otros nonces y se informa un error explícito si ninguna responde. Se mantienen los cuatro timestamps, la selección por RTT mínimo y el límite de desviación. Un reloj desincronizado o incierto sigue impidiendo el inicio.
- El dashboard repetía validación del plan y cálculos de ejecuciones históricas en el coordinador. En el control, validar el plan original tomó 0,51 s y consultar las 16 ejecuciones tomó 1,19 s. Se cachean planes validados por mtime y tamaño y los agregados de ejecuciones finalizadas; se deja de capturar continuamente recursos de ejecuciones históricas. Las respuestas globales de recursos se generan fuera del bucle del coordinador.

Se exportan recursos desde la preparación, se conservan errores con su clase y traceback y se identifican los timeouts del control baseline por host. No se cambian cuotas, tasas, semilla, duración, ventanas de 5 s ni deadlines de tráfico. La suspensión del pipeline conserva lease finito, vigilancia y restauración.

Plan de referencia: `2c3580be4272c69a94c0ee39a990b0d33b9aa8654f60ab35d120283d2e118245`; SHA-256 del archivo: `3a2b8445f025bd6e1625baf6901f024b10d07567beac12d633e09e665b1fa9dc`.

La validación real y sus resultados se adjuntan en `correccion-preparacion-validacion.json`. Un fallo de entrega de un evento conserva su estado de error; no se convierte en éxito ni se modifica el plan para evitarlo.

Validación real: `20261002T205918-8ad97411` completó 600 s, 21 agentes y cero errores HTTP de consultas concurrentes. Estado `completed_with_errors`: 7 351 completados / 553 fallidos, 91,66 % del payload; restauración verificada y plan idéntico. Los errores de entrega por evento permanecen explícitos.
