# CPU y receptor paralelo

Victim: 4 vCPU, cuatro procesos receptores independientes, supervisor y sockets TCP/HTTP/UDP SO_REUSEPORT. Cada conexion TCP permanece en un proceso; UDP se distribuye por flujo. Un solo flujo no se divide entre procesos. El supervisor termina todos los hijos si alguno falla; OpenRC mantiene el servicio persistente tras reinicios. Python 3.8+; SO_REUSEPORT requiere Linux. Sin --workers se conserva un proceso, incluido en otros receptores Enterprise.

Desde el control node, sin experimentos activos:

    python3 deploy/vm-lab/tools/benign-lab/scripts/install_parallel_receiver.py --workers 4

Utiliza las credenciales privadas del inventario y known_hosts estricto; no incorpora contrasenas en el repositorio. No ejecutar la reinstalacion durante un experimento.

Fixed: VM suscriptor 2 vCPU, diez namespaces existentes y diez procesos generadores. No se crean nuevas VMs. La topologia conserva estos tamanos para futuros despliegues.

Las pruebas comparativas reutilizan BENIGN_V1 y el mismo benign_plan.json/hash; las capacidades del perfil no se recalibran durante la comparacion. Ground truth permanece en ventanas de 5 s.

ESXi: 28 cores fisicos / 56 hilos; 90 vCPU encendidas despues del cambio (antes 86). Los hilos no equivalen a cores fisicos. Se iguala CPU shares normal por vCPU en DU/UE, conservando las reservas MHz de radio y limites ilimitados. Se conserva latencySensitivity high tras probar normal: normal redujo Ready BR/CU pero obtuvo menor payload total. Ver CPU_EXPERIMENT_RESULTS.md. Para reaplicar la politica seleccionada sin experimentos activos: python3 deploy/vm-lab/tools/benign-lab/scripts/apply_esxi_cpu_policy.py --latency high. No se asigna afinidad manual ni se reduce el numero de vCPU de radio sin pruebas especificas.

Rollback: restaurar CPU allocation y latencySensitivity desde la captura privada .runtime/benign-lab/cpu-upgrade/before.json; para reducir vCPU apagar limpiamente cada VM antes de cambiar Victim a 1 y suscriptor a 1. Restaurar /opt/benign-lab/agent.py.before-parallel y /etc/init.d/benign-lab-receiver.before-parallel en Victim y reiniciar el servicio. No borrar namespaces ni leases.
