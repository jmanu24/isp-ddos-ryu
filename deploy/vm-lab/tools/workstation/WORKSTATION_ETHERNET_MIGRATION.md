# Migración al enlace Ethernet directo

El 3 de octubre de 2026 se trasladó el transporte de las siete redes del laboratorio desde WiFi al cable PC–puerto 2 de ESXi. Las nueve VMs siguen en VMware Player: victim, pe, bng, suscriptor y ent-site-1…5. Radio, Core5G, RIC, Peering y control permanecen en ESXi. No se cambiaron IPs de los nodos, namespaces, capacidades, semillas, planes ni deadlines.

| Elemento | Configuración |
|---|---|
| PC | Ethernet 2, Realtek, 172.31.254.2/30, enlace 1 Gbps |
| ESXi | vmnic1, vSwitch-LAB-WIRED, LAB-WIRED-TRANSPORT sin VLAN |
| Relay | NIC adicional wired0, MAC 00:0c:29:d4:fd:ae, 172.31.254.1/30 |
| Pasarela Player | Conserva NAT VMnet8; WireGuard endpoint 172.31.254.1:51871 |
| Redes transportadas | VXLAN 800, 801, 804, 805, 806, 807, 808 sobre WireGuard |
| Administración desde esta PC | Ruta persistente 192.168.18.154/32 por 172.31.254.1 |

Windows dirige el tráfico NAT de la pasarela hacia Ethernet. El relay reenvía exclusivamente el tráfico de administración de 172.31.254.2 a 192.168.18.154, con NAT por eth0. WiFi conserva Internet y el acceso a otras direcciones de la LAN. El dashboard conserva http://192.168.18.154:8780. El puerto de monitoreo Windows sigue limitado a loopback y publicado al control mediante SSH.

## Persistencia

La dirección y ruta Windows están en PersistentStore. El relay conserva su nueva MAC en /etc/lab-overlay/mac-names.json, la IP en /etc/network/interfaces y las reglas específicas en /etc/local.d/lab-wired.start. No se vaciaron reglas existentes. Las políticas del portgroup de transporte rechazan promiscuidad, cambio de MAC y transmisiones con MAC ajena.

En .runtime/benign-lab/workstation.json se agregaron relay_network=LAB-WIRED-TRANSPORT, relay_endpoint=172.31.254.1 y transport=ethernet-direct. workstation_start_policy.py admite la dirección explícita porque VMware Tools no publicó inmediatamente la NIC añadida en caliente. El arranque Windows reutiliza esta dirección y no vuelve a configurar el endpoint WiFi. No se publican archivos privados ni claves.

## Controlador y validación

El controlador Ethernet Microsoft 1.0.0.14 presentaba interrupciones durante las pruebas. Se instaló el paquete firmado del fabricante Gigabyte para B460M DS3H, compatible con el ID PCI exacto del adaptador: versión instalada 10.50.511.2021. No requirió reiniciar Windows. Se retiraron los ajustes temporales de ARP, offload y seguridad utilizados para diagnosticar.

Las nueve VMs respondieron sin pérdidas en la comprobación de conectividad. La prueba de MTU 1500 (1472 bytes ICMP con DF) pasó. La transferencia de 128 MiB por el overlay alcanzó 364 Mbps en la última prueba (425 Mbps en una medición anterior); esta medida incluye NAT, WireGuard y VXLAN y no equivale al rendimiento máximo de cada dominio.

La prueba de bajo volumen 20261003T191724-7eaded32 completó 126/126 eventos TCP/HTTP/UDP, en ambos sentidos, con 21 agentes. El pipeline baseline se restauró al terminar. Una primera prueba con un único paquete UDP de 1200 bytes al final de seis segundos registró seis deadlines; la comprobación final utilizó paquetes de 200 bytes con la misma cuota. Esto cambió solo el plan de diagnóstico, no los planes del usuario.

SHA-256 del plan científico original: 3a2b8445f025bd6e1625baf6901f024b10d07567beac12d633e09e665b1fa9dc.
plan_hash: 2c3580be4272c69a94c0ee39a990b0d33b9aa8654f60ab35d120283d2e118245.

## Reversión del transporte

Si se desconecta el cable, retirar en Windows únicamente la ruta 192.168.18.154/32 de Ethernet 2. Por WiFi, acceder al control y cambiar relay_endpoint a la IP actual del relay en VM Network (al migrar era 192.168.18.143), relay_network a VM Network y transport a wifi. Ejecutar el arranque habitual Windows para actualizar WireGuard. No encender los originales ESXi de las nueve VMs: comparten MAC/IP con las copias activas en Player.

El cable no tiene conmutación automática a WiFi. La actualización del controlador no se revierte como parte de una reversión del transporte. La reserva 172.31.254.0/30 es exclusiva del enlace directo y no tiene puerta de enlace predeterminada ni DNS.

Fuente del controlador: https://www.gigabyte.com/Motherboard/B460M-DS3H-rev-10/support#support-dl-driver-lan

