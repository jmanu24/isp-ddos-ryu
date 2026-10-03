# Ampliación de CPU — PE y peer-router

Aplicada el 2 de octubre de 2026 al finalizar el diagnóstico de la ejecución 20261002T195854-d37260d9.

| Nodo | Ubicación | Antes | Ahora |
|---|---|---:|---:|
| pe | Windows / VMware Player 192.168.18.45 | 1 vCPU | 2 vCPU |
| peer-router | ESXi 192.168.18.135 | 1 vCPU | 2 vCPU |

Se confirmó que no había experimentos activos. Ambos nodos se apagaron de forma ordenada; se modificó PE solo después de verificar que su VMX no estaba en ejecución. PE usa un socket y dos cores virtuales; su VMX anterior queda en work/migration/production/pe/converted/pe/pe.vmx.before-cpu2. El original PE de ESXi se conserva apagado, con su configuración anterior. peer-router se amplió con govc y arrancó en ESXi. Los dos invitados confirmaron 2 CPU.

Se persistieron las dos asignaciones en deploy/vm-lab/topology.yaml y el denominador vcpus=2 de CPU Ready para peer-router en lab.connected.yaml. El dashboard se reinició para aplicar esa configuración, sin ejecutar un experimento de producción. RAM, discos, redes, MAC, IP y plan científico se conservan. Las nueve VMs trasladadas a Windows suman ahora 14 vCPU; el gateway Windows usa 2 adicionales. ESXi agrega una vCPU activa respecto al estado anterior por peer-router.

PE confirmó OVS br-ent, DPID 0000000c29d1c927, cinco puertos de datos y conexión al controlador. peer-router conserva su ruta a victim-web por 10.30.0.1. El NTP de peer-router no arrancaba automáticamente; la primera validación rechazó un desfase de 487 ms sin transmitir payload. Se habilitaron persistentemente systemd-timesyncd y la ruta NTP ya existente. NTPSynchronized=yes quedó confirmado.

Prueba funcional 20261002T203226-7251a6d6: 21 generadores, 126 eventos TCP/HTTP/UDP en ambas direcciones. 124 completed y 2 failed; 75600 bytes TX y 73200 RX, frente a 151200 bytes programados. Fixed 60/60, Enterprise 30/30 y Peering 6/6 completos. Mobile 28/30: UDP DL de UE2 y UE4 agotó el deadline. La prueba terminó completed_with_errors, sin aborto del coordinador; detección y mitigación quedaron restauradas. Es una prueba de conectividad de bajo volumen, no una medición de mejora de rendimiento ni un reemplazo del baseline de 600 segundos.

El archivo científico conserva SHA-256 3a2b8445f025bd6e1625baf6901f024b10d07567beac12d633e09e665b1fa9dc y plan_hash 2c3580be4272c69a94c0ee39a990b0d33b9aa8654f60ab35d120283d2e118245. BENIGN_V1, semillas y ground truth de 5 segundos no cambian.

No se aumentó CPU de las demás VMs: victim ya tiene cuatro vCPU; Fixed no mostraba saturación global; varias VMs ESXi tienen Ready elevado, y añadir vCPU sin revisar planificación podría empeorar su espera. El backend benign-lab tiene un límite de un hilo que no se resuelve solamente añadiendo vCPU al control. peer-router podrá aprovechar más CPU del sistema, pero el generador agregado actual aún necesita paralelización para garantizar uso de varias CPU.

Reversión, solo sin experimentos activos: apagar PE ordenadamente, restaurar su VMX previo y arrancarlo; apagar peer-router ordenadamente, aplicar govc vm.change -vm peer-router -c 1 y arrancarlo; devolver vcpu=1 en topology.yaml y vcpus=1 en CPU Ready, y reiniciar el dashboard. Verificar NTP y servicios tras cada arranque. No encender el original PE de ESXi mientras su copia Windows siga activa.

Pendiente para evaluar el beneficio: repetir el mismo plan de 600 s y comparar recursos por VM, proceso y CPU Ready. También siguen pendientes el diagnóstico del aborto anterior y los deadlines UDP de Mobile.
