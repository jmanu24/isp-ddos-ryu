# Continuidad del baseline y telemetría de Peering

La consulta de archivos nfcapd se desacopla del ciclo principal de Ryu mediante una única consulta pendiente. La decodificación conserva el mecanismo existente tpool; el controlador recoge el resultado una sola vez cuando está listo. No se lanzan consultas concurrentes al mismo colector ni se cambia el timeout del watchdog.

El modo asíncrono se habilita explícitamente en Ryu; otros consumidores conservan el contrato síncrono. Los fallos de consulta quedan registrados con traceback y liberan la consulta pendiente. Se registra la duración de las consultas. Durante una consulta pendiente no se deben interpretar los ciclos sin resultados Peering como un volumen de tráfico medido igual a cero: el colector trabaja con exportaciones y tiene latencia.

El error de pérdida del baseline incluye expected_run_id, el estado observado y heartbeat_age_s. Sigue abortando si el estado no está activo, no está cleared, pertenece a otra prueba o supera 30 s. No se genera un heartbeat artificial para encubrir un controlador bloqueado.

Despliegue: aplicar únicamente el cambio async_poll al controlador instalado y actualizar telemetry/bgp_adapter.py. La copia instalada de controller/ryu_controller_2.py difiere de la copia del repositorio; reemplazarla íntegra sin sincronizar config/settings.py puede introducir referencias de configuración incompatibles. Se mantienen copias de respaldo antes de modificar archivos.

Validación: tests/test_peering_async.py comprueba consulta única pendiente, entrega una vez, recuperación de errores y compatibilidad síncrona. Los tests de baseline/benchmark verifican aislamiento por dominio y restauración explícita de UE. El plan BENIGN_V1, semillas, ground truth 5 s y plan_hash no se modifican.
