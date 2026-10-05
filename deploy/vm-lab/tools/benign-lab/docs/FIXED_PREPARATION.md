# Preparación de Fixed antes de cada prueba

La preparación real actualiza source_ip y session_id consultando las direcciones IPv4 de la interfaz dentro del namespace correspondiente y las sesiones IPoE activas del BNG. Exige dos lecturas estables y direcciones únicas antes de resolver los grupos de agentes. El número esperado se obtiene de los nodos configurados; no depende de una cifra fija de diez.

Se ejecuta tanto para B0 como para B0+attack con pipeline enabled. En ese caso no adquiere lease baseline, no cambia restricciones de detección/mitigación y no reconecta sesiones. Guarda fixed_preparation en run.json, actualiza lab_snapshot.json y recalcula lab_hash. El archivo benign_plan.json y su plan_hash permanecen intactos.

En pipeline baseline, BaselineGuard reutiliza el mismo procedimiento conservando la recuperación existente de concesiones sin sesión activa y la restauración del pipeline al finalizar. La validación de IP en la interfaz del agente permanece activa. Una prueba sin Fixed o en simulación no necesita consultas al BNG.

Validación: pruebas de IP renovada, contexto sin namespace, namespace equivocado y preparación de B0/B0+attack sin entrar en baseline; regresiones de restauración y benchmark. Consulta real de diez namespaces y sesiones correlacionadas. Las direcciones encontradas son evidencia del momento de preparación y no se fijan como configuración permanente.
