# VM Lab webtool

Panel web para gestionar el laboratorio distribuido de 16 VMs (`deploy/vm-lab`),
equivalente al webtool del laboratorio Mininet (`webtool/` en la raiz del repo)
pero para VMs reales sobre ESXi. Proceso y puerto totalmente separados del
webtool de Mininet (puerto **8070**, no 5050) -- no comparten codigo.

## Requisitos

Corre en el control node (esta VM, `isp-ddos-ryu`), que ya tiene:
- `sshpass` + `ssh` con acceso a las 16 VMs (credenciales en `webtool/inventory.py`)
- `govc` + `../.govc.env` (power on/off/estado)
- `ansible-playbook` + `../ansible/` (bring-up orquestado)

No necesita `root` (a diferencia del webtool de Mininet): todo es SSH/subprocess.

## Uso

```bash
cd deploy/vm-lab
pip install flask flask-socketio  # si no estan ya instalados
python3 -m webtool.app
```

Abrir `http://<control-node>:8070/`.

## Que hace

- **Topologia**: los 4 dominios (mobile/broadband/enterprise/bgp) + infraestructura
  compartida (orchestrator/pe/victim), con power state (govc) y señales de
  servicio por rol (docker, systemd, E2/F1/RRC segun corresponda -- ver
  `webtool/status_checks.py`).
- **Power / Bring-up**: botones para power on/off individual (govc) y para
  correr `ansible/playbooks/reconnect_mobile_domain.yml` completo o por paso
  (`--tags`), streameando la consola de Ansible en vivo. Reusa el playbook
  ya validado -- no reimplementa su logica.
- **Ataques DDoS**: lanza/detiene trafico real hacia la victim compartida
  (10.55.0.100) desde una fuente real por dominio (`webtool/attacks.py`):
  hping3 en enterprise/bgp, flood a nivel de sockets de kernel en
  broadband/mobile (mismo mecanismo que `simulation/bng_flood.py`, ya que
  hping3 no funciona sobre esas interfaces).
- **KPM / Mitigacion**: polling del bridge xApp (`ric:8767/kpm`) y de los
  logs del contenedor `rc_actuator` para eventos de deteccion/mitigacion.
- **Metricas**: CPU%, mem% y throughput por interfaz por VM, muestreado por
  SSH (sin agente), graficado en vivo con Chart.js.
- **Logs**: visor on-demand de journalctl/docker logs/archivos por
  componente, para troubleshooting (`webtool/logs.py`).

## Notas

- El polling de estado/metricas es best-effort: una VM apagada o inalcanzable
  simplemente reporta `reachable: false` / `power: poweredOff`, no rompe el loop.
- Solo un job de Ansible corre a la vez (el propio playbook hace power-cycle
  de VMs compartidas -- correr dos en paralelo correria).
