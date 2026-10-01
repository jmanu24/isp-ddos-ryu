# Operación conectada — 1 de octubre de 2026

Esta actualización reemplaza los requisitos de Python y los estados pendientes del informe de inspección anterior. BENIGN_V1, perfiles, semillas, plan_hash y ground truth de 5 s siguen conservados.

## Estado actual

- ent-site-2…5 encendidas mediante govc; cinco sitios accesibles por SSH y receptores habilitados.
- Fixed ampliado a diez macvlans y diez sesiones IPoE activas en accel-pppd/FreeRADIUS, incluida macvlan3 anteriormente sin sesión. Se modificaron el generador de inventario, la variable generada, el límite del agente y la configuración persistente de suscriptor.
- El agente Fixed mantiene DHCP y rutas por origen con `--no-baseline`: no inicia su generador TCP_SYN low_and_slow anterior. Los escenarios de ataque siguen disponibles por el mecanismo existente; no deben iniciarse durante B0.
- Victim tiene una ruta persistente `10.20.0.0/24 via 10.92.0.2 dev eth1`. Conserva las IPs de abonado y devuelve respuestas por BNG en lugar de gestión. La misma ruta se agregó al rol Ansible victim.
- Peering mantiene victim por BR (10.30.0.1). Su reloj se corrigió con systemd-timesyncd y una ruta /32 al servidor NTP usado por control (185.125.190.58), vía control 10.30.0.3. Sólo NTP usa esa ruta de gestión.

## Versiones y pruebas

Control node: Python 3.8.10 en un venv propio. Agentes Ubuntu: Python 3.10.12. Victim Alpine: Python 3.14.7. Se sustituyó asyncio.timeout/timeout_at por deadlines compatibles, se usan Optional/Dict/List en modelos de la API y timeouts de asyncio en Python 3.8. `requirements.lock` contiene las versiones resueltas en el controlador. Suite: 22 pruebas aprobadas en Python 3.8/Linux, incluyendo agentes reales, cancelación y API.

El piloto conjunto prueba 21 contextos: cinco UE, diez IPs Fixed, cinco sitios y un generador Peering. TCP, HTTP y UDP en ambos sentidos; Enterprise también usa receptores intersite. Resultados y límites volumétricos: `CONNECTED_PILOT.json`. Resultado final: 126 eventos ejecutados, 149000 de 151200 bytes programados. Seis transferencias quedaron por debajo del volumen; la corrida se marca completed_with_errors y el panel muestra advertencias/shortfall_bytes. Es un piloto de conectividad de baja carga, no la corrida científica BENIGN_V1 de 600 s ni una calibración de capacidades.

## Ubicación y servicios

Aplicación en control: `/home/ubuntu/isp-ddos-ryu/deploy/vm-lab/tools/benign-lab`.

- Configuración: `config/lab.connected.yaml`.
- Controlador systemd: `benign-lab-web.service`, usuario ubuntu, escucha 127.0.0.1:8780.
- Agentes en VMs: `/opt/benign-lab/agent.py`.
- Receptores Ubuntu: `benign-lab-receiver.service` en cinco sitios.
- Receptor Alpine: OpenRC `benign-lab-receiver` en victim.
- Datos, env y credenciales: `/home/ubuntu/isp-ddos-ryu/.runtime/benign-lab`, excluido de Git y del ZIP. Archivos de credenciales 0600 y directorio 0700.

Las conexiones a workers se originan en control. Las VMs Ubuntu usan labadmin. **Victim Alpine conserva el acceso root existente** para el receptor; no se creó labadmin ni se cambiaron sus credenciales. La contraseña no aparece en YAML, argv, planes ni exportaciones. ssh_bridge.py usa sshpass -e con variable de entorno o JSON protegido para el modo de salto. Las claves de host se registraron desde la red del controlador.

## Acceso al panel

Se abrió un túnel en el equipo de esta sesión: `http://127.0.0.1:8780`. Desde otro equipo:

```bash
ssh -N -L 8780:127.0.0.1:8780 ubuntu@192.168.18.154
```

Abrir esa dirección. El servicio sigue en loopback; no se expuso un panel sin token a la LAN.

## Ejecución y parámetros pendientes

Completar `capacity_mbps` de los cuatro dominios después de calibrarlos. Son los únicos campos de mapeo pendientes en la API. No se inventaron capacidades a partir de la velocidad de las vNICs. El piloto usa una capacidad de referencia sólo para expresar tasas pequeñas; no cambia la configuración principal.

```bash
cd /home/ubuntu/isp-ddos-ryu/deploy/vm-lab/tools/benign-lab
.venv/bin/benign-lab inspect-mapping --lab config/lab.connected.yaml
```

Después de completar capacidades: generar/importar un plan en el panel, validar mapeo e iniciar Laboratorio a velocidad 1. Reutilizar el mismo plan en B0 y B0+attack. Reconfirmar leases DHCP y sesiones antes de la campaña; las IPs del YAML son el snapshot observado. Las métricas son payload; UDP UL confirma envío local. Certificar entrega y recorrido con capturas/contadores externos.

Para ejecutar el controlador desde otro equipo manteniendo el salto, definir en cada nodo `control_node: ubuntu@192.168.18.154`, `control_identity_file`, `bridge_path` a ssh_bridge.py desplegado y `credentials_file` al archivo protegido en control. El despliegue actual ya corre dentro de control.

## Recuperación

Respaldos Fixed en `.codex-backups/fixed10-*` y archivos `.before-fixed10` en suscriptor. Victim conserva `.before-benign-route`. No se hicieron commits ni se enviaron cambios al repositorio remoto. Restaurar sólo piezas necesarias y comprobar sesiones/rutas. Secretos/runtime excluidos de Git.


