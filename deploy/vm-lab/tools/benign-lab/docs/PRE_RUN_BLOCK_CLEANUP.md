# Limpieza de restricciones antes de cada prueba

Todas las corridas del laboratorio con baseline_control usan BaselineGuard durante preparación, independientemente del escenario. Se suspenden temporalmente detección/mitigación, se liberan restricciones registradas por el controlador, se restablecen presupuestos UE en los dominios incluidos, se verifican drop OpenFlow residuales y se reconectan/verifican sesiones Fixed. Todo queda en block_preparation y lab_snapshot.

Con pipeline enabled, la suspensión se mantiene durante preflight y sincronización de todos los agentes. Justo antes de programar el origen experimental se confirma la suspensión, se libera la lease y se confirma restauración. La ventana medida conserva detección y mitigación activas: los falsos positivos no se limpian ni ocultan durante tráfico.

Con pipeline baseline, la lease se mantiene durante la medición, con watchdog y restauración al finalizar. Si limpieza, verificación o restauración fallan, started_at queda vacío y la corrida falla antes del tráfico. La lease finita y finally protegen la restauración tras errores/cancelación.

Se reutilizan operaciones existentes de liberación de actuadores; no se vacían tablas de encaminamiento, flujos ajenos ni reglas no identificadas. Un drop residual no identificado bloquea el inicio. Los benchmarks mantienen sus comprobaciones de dominio. Simulación y transporte local sin controlador no tienen bloqueos de laboratorio que limpiar.

No cambian umbrales, tasas, semillas ni planes. Las restricciones generadas dentro de una corrida con pipeline activo forman parte del resultado experimental y se conservan en su auditoría; se liberan al preparar la siguiente.
