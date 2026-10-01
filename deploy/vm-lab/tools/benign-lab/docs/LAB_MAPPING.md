# Mapeo de nodos reales

## Identidades lógicas y caminos de datos

| Dominio | Identidades del plan | Camino que debe proporcionar el laboratorio |
|---|---|---|
| Mobile | ue1…ue5 | UE → DU/CU → 5GC → backbone mobile → victim |
| Fixed | fixed1…fixed10 | sesión IPoE/abonado → BNG → backbone fixed → victim |
| Enterprise | ent-site-1…ent-site-5 | sitio → PE/OVS/SDN → victim o sitio remoto |
| Peering | peer-flow1…peer-flow100 | generador → peer-router → BR/PE → victim |

Backbones de la referencia: Mobile `10.91.0.0/30`, Fixed `10.92.0.0/30`, Peering `10.93.0.0/30`. Son información de topología: el controlador no asigna automáticamente estas direcciones. El destino central permanece `10.55.0.100`.

`source` es una identidad lógica. El agente usa las direcciones/rutas de la VM o namespace donde corre. Para observar IPs distintas, usar namespaces/interfaces/rutas distintos. Varios abonados en un solo namespace conservan sus etiquetas lógicas, pero compartirán dirección IP. Si el laboratorio denomina la primera UE `ue`, mapear el identificador lógico `ue1` al namespace `ue`; no es necesario renombrar el plan.

## Cuatro adaptadores

```yaml
nodes:
  ue1:
    adapter: netns
    namespace: ue
    sudo: true
  ue2:
    adapter: ssh_netns
    host: 10.10.0.11
    user: lab
    namespace: ue2
    sudo: true
    python: /usr/bin/python3
    agent_path: /opt/benign-lab/benign_lab/agent.py
    identity_file: /home/lab/.ssh/id_ed25519
    port: 22
  ent-site-1:
    adapter: ssh
    host: 10.10.0.21
    user: lab
  'peer-flow*':
    adapter: local
```

Las coincidencias exactas tienen prioridad sobre patrones. Si dos patrones coinciden y no hay entrada exacta, se rechaza el mapeo. La capacidad se fija al generar el plan. Cambiar `capacity_mbps` en el mapeo no cambia las tasas de un plan ya materializado.

## Preparación de cada host ejecutor

1. Instalar Python ≥3.11, OpenSSH e `iproute2`/`iputils-ping` en Linux. El agente no necesita FastAPI ni PyYAML.
2. Copiar `benign_lab/agent.py` a la ruta configurada, por defecto `/opt/benign-lab/benign_lab/agent.py`.
3. Configurar claves SSH y verificar manualmente la huella del host. El adaptador usa `BatchMode=yes` y `StrictHostKeyChecking=yes`; no acepta contraseñas interactivas ni huellas desconocidas.
4. Proporcionar el permiso necesario para `ip netns exec`. `sudo: true` usa `sudo -n`: configurar en el laboratorio los permisos adecuados al comando requerido. No cambiar sudoers automáticamente desde esta herramienta.
5. Sincronizar relojes del controlador y VMs, por ejemplo con chrony/NTP. Se rechaza el inicio si el reloj anunciado supera `max_clock_skew_s` respecto al controlador. Esta es una comprobación aproximada que incluye latencia de gestión, no una certificación NTP.
6. Verificar desde **el namespace/VM de origen** que las rutas hacia victim y los sitios empresariales atraviesan la infraestructura correcta.

Un solo proceso se prepara por combinación de comando/host/namespace. Todos sus eventos se transfieren antes de comenzar. Tras la preparación, el controlador fija un único epoch `start_unix` y lo comunica por stdin. Cada agente convierte ese epoch a un reloj monotónico local. Evita abrir una conexión SSH por evento y registra cualquier demora residual.

## Receptores

En victim y cada destino intersite, ejecutar:

```bash
python3 /opt/benign-lab/benign_lab/agent.py receiver --host 0.0.0.0 --tcp-port 9001 --udp-port 9002 --http-port 8088
```

Esos puertos deben coincidir con `targets`. Restringir su acceso al laboratorio. Los receptores manejan sesiones concurrentes. TCP usa un protocolo de control interno seguido de payload; HTTP usa GET/POST; UDP DL usa solicitudes pequeñas para obtener datagramas del tamaño planificado.

Antes de tráfico real, el panel **Validar mapeo** comprueba configuración, direcciones permitidas y adaptadores. Al iniciar, cada agente comprueba conexiones TCP/HTTP y disponibilidad de ping. UDP, routing y capacidades de ICMP se validan mediante el piloto; una preparación exitosa no confirma la entrega de UDP.

## Prueba piloto recomendada

- Materializar un plan corto y revisar sus advertencias: puede omitir picos y quedar completamente dentro del warmup.
- Ejecutar tráfico real y comprobar eventos fallidos, desfase, bytes y contadores del receptor.
- Capturar por dominio los flujos L3/L4 reales. Comparar payload planificado con volumen observado por interfaces/Ryu, considerando overhead y retransmisiones.
- Después ejecutar el plan completo de 600 s con las capacidades calibradas.
- Para una campaña emparejada, conservar el JSON, mapeo, versiones y snapshot de servicios. Cambios de mapeo alteran `lab_hash`; no cambian el plan, pero sí la comparabilidad experimental.

Los medios reales de aprovisionamiento IPoE/5G y las interfaces de las 23 VMs no se proporcionaron. El proyecto deja esas decisiones visibles en YAML y no inventa una configuración de red ejecutable para ellas.
