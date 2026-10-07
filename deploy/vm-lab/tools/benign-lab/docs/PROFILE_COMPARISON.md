# Comparación automática classic / persistent

En Pruebas y programación, el botón Ejecutar comparación de 18 pruebas crea una única serie persistente. No inicia nada hasta que el usuario lo pulse. Usa los tres planes de referencia de semillas 1, 2 y 3, con sus hashes existentes y duración de 600 s. Ignora las opciones seleccionadas en Monitor. Usa lab, B0, baseline, velocidad 1 y pausa de 60 s después de cada prueba, salvo la última.

| Bloque | Pasos |
|---|---|
| 1 | S1 classic → S1 persistent → S2 classic → S2 persistent → S3 classic → S3 persistent |
| 2 | S2 persistent → S2 classic → S3 persistent → S3 classic → S1 persistent → S1 classic |
| 3 | S3 classic → S3 persistent → S1 classic → S1 persistent → S2 classic → S2 persistent |

Son tres repeticiones por semilla y perfil. Duración mínima: 3 h 17 min; preparación y limpieza prolongan la duración real. El servidor guarda la secuencia, SHA256 de cada plan y run_ids; cada run recibe series_id, repetition_index y comparison_block. Los planes referenciados no se pueden borrar mientras la serie esté pendiente o activa.

El panel muestra el esquema, 0/18 hasta 18/18 iniciadas, los identificadores de runs y una lista desplegable del orden. Los enlaces permiten abrir cada ejecución. Cancelar serie después de la prueba actual deja terminar el tráfico y la limpieza.

La ejecución espera que termine cualquier prueba activa. completed_with_errors permite continuar y conserva la evidencia. failed/stopped/interrupted detiene la serie. Una restauración no confirmada requiere revisión; un reinicio mientras starting/running deja attention y no repite una ejecución ambigua automáticamente. No se admite otra comparación pendiente o activa.

La previsualización verifica planes completos, semillas, duración, capacidades iguales y compatibilidad con las capacidades actuales del laboratorio. Al lanzar cada paso se vuelve a verificar su SHA256; los cambios de bytes detienen la serie. No cambiar capacidades, umbrales o configuración durante la comparación. La garantía criptográfica cubre los planes; los umbrales se documentan en la auditoría de cada ejecución, no quedan bloqueados por esta función.

GET /api/comparison-plan muestra la secuencia. POST /api/comparison-plan/start la encola. Ambos usan el control de acceso existente. El botón inicia inmediatamente o espera a que termine una prueba activa; no se añadieron horarios personalizados para esta comparación. Cerrar el navegador no detiene el trabajo; el nodo control debe permanecer encendido.
