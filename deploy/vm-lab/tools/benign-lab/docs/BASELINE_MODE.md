# Tráfico baseline

En Ejecución, selecciona Laboratorio, B0 y Pipeline: Tráfico baseline,
sin detección ni mitigación. La opción predeterminada mantiene el pipeline
activo. Baseline no admite B0+ataque ni demostración.

El controlador conserva telemetría, correlación y forwarding, pero omite
detección, decisión y mitigación. Una concesión temporal identifica la ejecución
y caduca a duración+240 segundos: el pipeline se reactiva aunque el dashboard
muera. El gestor retira la concesión y verifica restauración al completar,
parar, fallar o perder el heartbeat; en este último caso detiene el tráfico.

Antes del arranque, el controlador libera los bloqueos que tiene identificados
mediante sus adaptadores habituales. El gestor restaura y comprueba las cinco
UE con max_prb=100, verifica ausencia de drops OpenFlow de mitigación en PE,
reconecta únicamente leases Fixed sin sesión BNG y exige diez IP estables
que coincidan con las sesiones activas. No elimina reglas no identificadas.
Si queda una restricción desconocida, el experimento falla antes de iniciar.

El mapeo baseline_control de config/lab.connected.yaml declara host/usuario
SSH del controlador, PE, BNG, suscriptor y URL RIC. BENIGN_SSH_PASSWORD y
BENIGN_PE_SSH_PASSWORD se suministran por el EnvironmentFile privado del
servicio. No incluir valores de credenciales en Git ni en exportaciones.

Despliegue: instalar config/baseline.py en el controlador y aplicar la importación
y la condición baseline_active(self.orchestrator) a su versión compatible de
ryu_controller_2.py; preservar la configuración y código específicos de la VM.
Reiniciar ryu-manager después del cambio. Instalar la herramienta actualizada
y su EnvironmentFile, y reiniciar benign-lab-web. La suspensión comienza solo
cuando el usuario inicia una ejecución con pipeline=baseline.

run.json contiene pipeline, baseline_control.preflight y restoration. Los logs
registran la suspensión/restauración; lab_snapshot.json contiene IP y sesiones
reales de ese arranque. BENIGN_V1, semillas, benign_plan.json, plan_hash y las
ventanas ground truth de cinco segundos se conservan. Las IP del mapeo son
metadatos de ejecución y no modifican el plan reutilizable.

Validación: 18 pruebas del gestor/API/compatibilidad/controlador; preflight
real de 21 contextos; piloto de 5s con ocho eventos TCP UL/DL sobre Mobile,
Fixed, Enterprise y Peering, 4800 bytes TX y 4800 RX, estado completed;
segundo piloto detenido manualmente, estado stopped y cero bytes emitidos.
Ambos confirmaron restauración del pipeline y copia exacta del plan.
No se ejecutó aquí el baseline científico completo de 600 segundos.

Este modo evita la intervención del pipeline; no elimina límites de capacidad,
fallos de conectividad, pérdidas o retrasos del generador y del laboratorio.
