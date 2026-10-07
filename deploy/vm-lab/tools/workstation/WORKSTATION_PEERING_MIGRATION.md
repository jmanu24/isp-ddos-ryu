# Migración de Internet Peering a VMware Player — 7 octubre 2026

Migradas br y peer-router desde ESXi 192.168.18.135 a la PC 192.168.18.45. Se preservaron IP, MAC, PCI, discos y configuración de servicios. Cada VM mantiene 2 vCPU; br conserva 3072 MiB y peer-router 2048 MiB. Los originales de ESXi permanecen apagados y recuperables.

## Redes

PC: br y peer-router comparten el segmento privado LAB-WIFI-802 (el nombre histórico no implica uso de WiFi). br también utiliza LAB-WIFI-800 para MGMT y LAB-WIFI-808 para BACKBONE_PEERING, existentes en la PC. No se reinició ni se añadió una NIC al gateway compartido. La copia de discos utilizó la ruta Ethernet a través del gateway; la administración externa de la PC sigue por su IP WiFi existente.

Direcciones conservadas: br 10.10.0.3, 10.30.0.1, 10.93.0.2; peer-router 10.30.0.2. El backbone comunica br con pe; tráfico entre las VMs del dominio usa el segmento local de Player.

El nodo control conserva 10.30.0.3 en su segmento ESXi, que ya no comparte broadcast con el Peering local de la PC. Por ello se añadió una ruta /32: 10.30.0.2 via 10.10.0.3 dev ens192 src 10.10.0.254. Persiste mediante benign-peering-workstation-route.service. En peer-router, peering-management-route.service instala 10.10.0.0/24 via 10.30.0.1 y el next-hop del servidor NTP 185.125.190.58 via 10.30.0.1. No se añadió un default general ni se redistribuyeron rutas administrativas a BGP.

El inventario admite management_ip explícito y peer-router usa 10.30.0.2. La ubicación de ambas VMs queda workstation/192.168.18.45/ethernet_direct. El backend privado, el arranque de Windows y la política de protección de originales ESXi incluyen ambas VMs.

## Validación

- SSH desde el nodo control a ambas VMs.
- BGP br (AS65000) con peer-router (AS64512) establecido.
- frr, flow y softflowd-peering de br activos; nfcapd del controlador activo.
- br y peer-router hacia victim: 6/6 pings; Enterprise y Fixed hacia peer-router: 6/6 pings.
- Benchmark diagnóstico 20261007T092246-7c99d2b7: 20 s, dos eventos TCP UL/DL de 65536 bytes cada uno, completos, receptor confirmado, shortfall=0, pipeline restaurado. Usa preparación exclusiva Peering y se identifica como diagnóstico; no valida rendimiento máximo.
- NetFlow decodificado en /var/cache/nfcapd/r1 identifica 10.30.0.2 → 10.55.0.100:9001. Capturas nuevas presentes. Hubo registros posteriores al cierre del smoke; esta comprobación demuestra exportación, no una garantía de latencia de telemetría.
- Sondas CPU/memoria de br y peer-router recibidas por /api/vm-resources tras recargar monitores.
- NTP sincronizado en br y peer-router. Se conserva el servidor NTP público original; la dirección administrativa del control no actúa como servidor NTP.
- SHA256 de los discos exportados y copiados coincide: peer-router ba94a8529579ec3b5e22d95c65654d45f3490e976cfc749864326289eabe9794; br 3e09e8006f225a181eee101f92dea6bc4b2091371c069623ae6e5883d50ca995.

Una primera sonda fue detenida antes del tráfico por preparación global dependiente de Mobile. Se conservó el fallo; el smoke final usa el mecanismo de benchmark por dominio y no omite controles de su dominio. No se intervinieron radio, core ni UEs.

## Consecuencias experimentales

Se liberan las asignaciones de 4 vCPU y 5 GiB de RAM de estas VMs en ESXi. No se recalibró la capacidad de Peering ni se modificaron BENIGN_V1, semillas, planes de referencia o ground truth 5 s. La ubicación física ha cambiado: futuras ejecuciones documentan br/peer-router en workstation_guests. Los resultados anteriores y posteriores no deben mezclarse como condiciones físicas idénticas. Un benchmark de capacidad posterior será otra medición, no una modificación de los planes ya materializados.

## Reversión

Detener pruebas, terminar y apagar ordenadamente br y peer-router en Player; verificar que ambas estén apagadas. Restaurar los archivos de registro previos guardados en .runtime/benign-lab/peering-migration/registration-backup y la configuración privada Workstation correspondiente; retirar los nombres nuevos del arranque de PC. Deshabilitar benign-peering-workstation-route.service y eliminar la ruta /32 de control. Después, y solo después de comprobar que no hay copias Player encendidas, encender ambos originales ESXi. Revalidar SSH/BGP/tráfico y recargar interfaces de monitoreo. Las rutas nuevas del guest solo existen en las copias migradas; los originales conservan su configuración anterior. No borrar discos o exports hasta decidir que la reversión no será necesaria.
