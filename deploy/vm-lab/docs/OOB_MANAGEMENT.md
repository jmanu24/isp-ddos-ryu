# Gestión OOB de las VMs

La auditoría de las 24 VMs de la topología encontró MGMT existente en todos los nodos salvo peer-router y peer-router-2. Se agregaron NIC independientes en la red MGMT/VLAN 800 (segmento Workstation LAB-WIFI-800).

peer-router: MGMT 10.10.0.17/24, mgmt0, MAC 00:50:56:3a:b2:17; datos ens160 10.30.0.2/29, AS64512. peer-router-2: MGMT 10.10.0.18/24, mgmt0, MAC 00:50:56:3a:b2:18; datos ens160 10.30.0.4/29, AS64513.

Netplan /etc/netplan/99-benign-oob.yaml persiste por MAC. La ruta de gestión 10.10.0.0/24 va directamente por mgmt0, sin BR. Las rutas de datos y las sesiones BGP no cambian. El router-id de la plantilla BIRD se fija a la IP de datos para evitar cambios futuros por añadir gestión.

Inventario, generación Ansible y hosts prefieren management_ip/MGMT. Los ejecutores y monitores usan IP OOB para SSH, conservando source_ip/interface de datos. Copias VMX .pre-oob locales y copias de configuración en /var/backups/benign-oob y .runtime/benign-lab/oob permiten recuperar el cambio.

Se reiniciaron únicamente los dos peers para añadir hardware. RAN y otras VMs no se reiniciaron. Ambos BGP se verificaron Established y SSH OOB con claves iguales a las anteriores. La separación es de red virtual/gestión; en Workstation comparte el enlace físico Ethernet y el gateway de transporte con otras VLAN. No es una segunda conexión física independiente ni consola de gestión de hardware.
