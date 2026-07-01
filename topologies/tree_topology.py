#!/usr/bin/python3
"""
Topología árbol interactiva: Linux router → switches OpenFlow → hosts.

  r1 (Linux router, IP forwarding)
  ├── s1  (10.0.1.0/24)   ── h1, h4, h7, ...
  ├── s2  (10.0.2.0/24)   ── h2, h5, h8, ...
  └── s3  (10.0.3.0/24)   ── h3, h6, h9, ...

Al arrancar genera tráfico de fondo aleatorio entre hosts (ICMP, TCP, UDP a
baja tasa). Cada 60 s rota los flujos para simular patrones dinámicos.

Comandos disponibles en la CLI de Mininet:
  attack          — menú interactivo para lanzar un ataque DDoS
  stopattack      — detiene ataques (todos, o stopattack <id> para uno)
  listattacks     — muestra ataques activos
  stopnormal      — pausa el tráfico de fondo
  startnormal     — reanuda el tráfico de fondo
  listnormal      — muestra los flujos de fondo activos

Ataques soportados (requieren hping3):
  TCP SYN Flood, UDP Flood, ICMP Flood — fuente única o distribuido.

Uso:
    sudo python3 topologies/tree_topology.py
    sudo python3 topologies/tree_topology.py --switches 3 --hosts 9
"""

import argparse
import random
import sys
import threading

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch, Node
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel


# ---------------------------------------------------------------------------
# Tráfico de fondo (normal)
# ---------------------------------------------------------------------------

# Plantillas para los flujos normales.
# {dst} = IP destino, {port} = puerto aleatorio, {interval} = intervalo en µs.
# La tasa resultante es 1 000 000 / interval pps (1-5 pps por flujo).
_NORMAL_TEMPLATES = [
    ("ICMP", "ping -i 2 -c 99999 {dst}"),                          # ~0.5 pps
    ("TCP",  "hping3 -p {port} -i u{interval} {dst}"),             # 1-5 pps
    ("UDP",  "hping3 --udp -p {port} -i u{interval} {dst}"),       # 1-5 pps
]

_COMMON_PORTS = [80, 443, 53, 8080, 22, 3306, 5432]


class NormalTrafficManager:
    """
    Genera tráfico de fondo aleatorio entre hosts para simular una red con
    actividad legítima.

    Cada ronda asigna a cada host un destino aleatorio distinto y un protocolo
    al azar (ICMP/TCP/UDP) a baja tasa (1-5 pps). Tras `refresh_interval`
    segundos los flujos se detienen y se relanza una nueva ronda con pares
    distintos, simulando patrones de tráfico dinámicos.
    """

    def __init__(self, net, refresh_interval: int = 60):
        self._net = net
        self._refresh = refresh_interval
        self._flows   = []          # lista de dicts por flujo activo
        self._timer   = None
        self._active  = False
        self._lock    = threading.Lock()

    # ------------------------------------------------------------------
    # API pública
    # ------------------------------------------------------------------

    def start(self):
        with self._lock:
            if self._active:
                return
            self._active = True
        self._launch_round()

    def stop(self):
        with self._lock:
            self._active = False
            if self._timer:
                self._timer.cancel()
                self._timer = None
        self._kill_flows()

    @property
    def active(self):
        return self._active

    def snapshot(self):
        """Devuelve una copia de la lista de flujos activos."""
        with self._lock:
            return list(self._flows)

    # ------------------------------------------------------------------
    # Internos
    # ------------------------------------------------------------------

    def _kill_flows(self):
        with self._lock:
            flows = list(self._flows)
            self._flows = []
        for f in flows:
            p = f["proc"]
            try:
                p.terminate()
                p.wait(timeout=2)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    def _launch_round(self):
        self._kill_flows()
        if not self._active:
            return

        hosts = [h for h in self._net.hosts if h.name != 'r1']
        if len(hosts) < 2:
            return

        new_flows = []
        for src in hosts:
            others = [h for h in hosts if h is not src]
            dst    = random.choice(others)

            proto_idx         = random.randrange(len(_NORMAL_TEMPLATES))
            proto, template   = _NORMAL_TEMPLATES[proto_idx]
            port              = random.choice(_COMMON_PORTS)
            interval_us       = random.randint(200_000, 1_000_000)  # 1-5 pps
            dst_ip            = dst.IP()

            cmd = template.format(dst=dst_ip, port=port, interval=interval_us)
            proc = src.popen(cmd, shell=True)

            new_flows.append({
                "src":   src.name,
                "dst":   dst_ip,
                "proto": proto,
                "port":  port if proto != "ICMP" else None,
                "pps":   round(1_000_000 / interval_us, 1) if proto != "ICMP" else 0.5,
                "proc":  proc,
            })

        with self._lock:
            self._flows = new_flows

        if self._active:
            self._timer = threading.Timer(self._refresh, self._launch_round)
            self._timer.daemon = True
            self._timer.start()


# ---------------------------------------------------------------------------
# Tipos de ataque
# ---------------------------------------------------------------------------

_ATTACK_CMDS = {
    "syn_flood":  "hping3 -S --flood -p {port} {target}",
    "udp_flood":  "hping3 --udp --flood -p {port} {target}",
    "icmp_flood": "hping3 --icmp --flood {target}",
}

_ATTACK_LABELS = {
    "syn_flood":  "TCP SYN Flood",
    "udp_flood":  "UDP Flood",
    "icmp_flood": "ICMP Flood",
}


# ---------------------------------------------------------------------------
# CLI extendida
# ---------------------------------------------------------------------------

class AttackCLI(CLI):
    """
    CLI de Mininet con comandos para tráfico normal y ataques DDoS.
    """

    def __init__(self, net, normal_mgr: NormalTrafficManager, **kwargs):
        self._normal   = normal_mgr
        self._attacks  = {}     # attack_id -> {"procs": [(name, Popen)], "desc": str}
        self._next_id  = 1
        super().__init__(net, **kwargs)

    # ------------------------------------------------------------------
    # Helpers comunes
    # ------------------------------------------------------------------

    def _real_hosts(self):
        return [h for h in self.mn.hosts if h.name != 'r1']

    def _real_host_names(self):
        return [h.name for h in self._real_hosts()]

    # ------------------------------------------------------------------
    # Comandos: tráfico de fondo
    # ------------------------------------------------------------------

    def do_startnormal(self, _line):
        """Inicia (o reanuda) el tráfico de fondo entre hosts.

Uso: startnormal"""
        if self._normal.active:
            print("  El tráfico de fondo ya está activo.")
            return
        self._normal.start()
        print(f"  Tráfico de fondo iniciado "
              f"({len(self._real_hosts())} flujos, rota cada "
              f"{self._normal._refresh}s).")

    def do_stopnormal(self, _line):
        """Pausa el tráfico de fondo.

Uso: stopnormal"""
        if not self._normal.active:
            print("  El tráfico de fondo ya está detenido.")
            return
        self._normal.stop()
        print("  Tráfico de fondo detenido.")

    def do_listnormal(self, _line):
        """Muestra los flujos de tráfico de fondo activos.

Uso: listnormal"""
        flows = self._normal.snapshot()
        if not flows:
            estado = "activo" if self._normal.active else "detenido"
            print(f"  Sin flujos activos (estado: {estado}).")
            return

        alive = [(f, f["proc"].poll() is None) for f in flows]
        n_alive = sum(1 for _, up in alive if up)
        print(f"\n  Tráfico de fondo — {n_alive}/{len(flows)} flujos activos\n")
        print(f"  {'Src':<6} {'Dst':<15} {'Proto':<6} {'Puerto':<8} {'~pps'}")
        print(f"  {'-'*5} {'-'*14} {'-'*5} {'-'*7} {'-'*5}")
        for f, up in alive:
            port_str = str(f["port"]) if f["port"] else "—"
            status   = "" if up else " [fin]"
            print(f"  {f['src']:<6} {f['dst']:<15} {f['proto']:<6} "
                  f"{port_str:<8} {f['pps']}{status}")
        print()

    # ------------------------------------------------------------------
    # Comandos: ataques DDoS
    # ------------------------------------------------------------------

    def _pick_attack_type(self):
        print()
        print("  Tipo de ataque:")
        print("    1) TCP SYN Flood")
        print("    2) UDP Flood")
        print("    3) ICMP Flood")
        raw = input("  Elige [1]: ").strip() or "1"
        mapping = {"1": "syn_flood", "2": "udp_flood", "3": "icmp_flood"}
        key = mapping.get(raw)
        if not key:
            print("  Opción inválida.")
        return key

    def _pick_target(self):
        print()
        print("  Hosts disponibles como víctima:")
        for h in self._real_hosts():
            print(f"    {h.name}  →  {h.IP()}")
        raw = input("  IP o nombre del host víctima: ").strip()
        if not raw:
            return None
        if raw in self._real_host_names():
            return self.mn.get(raw).IP()
        return raw  # IP directa

    def _pick_port(self, attack_type):
        if attack_type == "icmp_flood":
            return 0
        raw = input("  Puerto destino [80]: ").strip() or "80"
        try:
            return int(raw)
        except ValueError:
            print("  Puerto inválido, usando 80.")
            return 80

    def _pick_sources(self, distributed):
        names = self._real_host_names()
        print()
        print(f"  Hosts disponibles: {', '.join(names)}")

        if not distributed:
            raw = input(f"  Host atacante [{names[0]}]: ").strip() or names[0]
            if raw not in names:
                print(f"  '{raw}' no existe.")
                return []
            return [self.mn.get(raw)]

        print("  Nombres separados por coma, o 'all' para todos.")
        raw = input("  Hosts atacantes [all]: ").strip() or "all"
        selected = names if raw.lower() == "all" else [s.strip() for s in raw.split(',')]
        invalid  = [n for n in selected if n not in names]
        if invalid:
            print(f"  Hosts no reconocidos: {', '.join(invalid)}")
            return []
        return [self.mn.get(n) for n in selected]

    def _launch_attack(self, sources, attack_type, target_ip, port):
        tmpl  = _ATTACK_CMDS[attack_type]
        procs = []
        for host in sources:
            cmd = tmpl.format(target=target_ip, port=port)
            p   = host.popen(cmd, shell=True)
            procs.append((host.name, p))

        aid      = self._next_id
        self._next_id += 1
        mode     = "distribuido" if len(sources) > 1 else "fuente única"
        src_str  = ', '.join(h.name for h in sources)
        desc     = (f"[#{aid}] {_ATTACK_LABELS[attack_type]} ({mode})  "
                    f"{src_str} → {target_ip}")
        if port:
            desc += f":{port}"
        self._attacks[aid] = {"procs": procs, "desc": desc}
        print(f"\n  Ataque lanzado: {desc}")
        print("  Usa 'stopattack' o 'stopattack <id>' para detenerlo.\n")

    def _terminate_procs(self, procs):
        for _name, p in procs:
            try:
                p.terminate()
                p.wait(timeout=3)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    def do_attack(self, _line):
        """Lanza un ataque DDoS desde uno o varios hosts.

Uso: attack  (menú interactivo)"""
        if not self._real_host_names():
            print("  No hay hosts disponibles.")
            return

        attack_type = self._pick_attack_type()
        if not attack_type:
            return

        print()
        print("  Modalidad:")
        print("    1) Fuente única")
        print("    2) Distribuido (varios hosts en paralelo)")
        raw         = input("  Elige [1]: ").strip() or "1"
        distributed = (raw == "2")

        sources = self._pick_sources(distributed)
        if not sources:
            return

        target_ip = self._pick_target()
        if not target_ip:
            print("  Destino no especificado.")
            return

        if target_ip in {h.IP() for h in sources}:
            print("  Un host no puede atacarse a sí mismo.")
            return

        port = self._pick_port(attack_type)
        self._launch_attack(sources, attack_type, target_ip, port)

    def do_stopattack(self, line):
        """Detiene ataques DDoS en curso.

Uso:
  stopattack        — detiene todos
  stopattack <id>   — detiene el ataque con ese ID"""
        line = line.strip()
        if not line:
            if not self._attacks:
                print("  No hay ataques activos.")
                return
            for aid, info in self._attacks.items():
                self._terminate_procs(info["procs"])
                print(f"  Detenido: {info['desc']}")
            self._attacks.clear()
        else:
            try:
                aid  = int(line)
                info = self._attacks.pop(aid, None)
                if info is None:
                    print(f"  No existe ataque #{aid}.")
                    return
                self._terminate_procs(info["procs"])
                print(f"  Detenido: {info['desc']}")
            except ValueError:
                print("  Uso: stopattack [id]")

    def do_listattacks(self, _line):
        """Lista los ataques DDoS activos.

Uso: listattacks"""
        if not self._attacks:
            print("  No hay ataques activos.")
            return
        print()
        for aid, info in self._attacks.items():
            alive  = sum(1 for _, p in info["procs"] if p.poll() is None)
            total  = len(info["procs"])
            print(f"  {info['desc']}  [{alive}/{total} procesos activos]")
        print()

    # ------------------------------------------------------------------
    # Limpieza al salir
    # ------------------------------------------------------------------

    def _cleanup(self):
        self._normal.stop()
        if self._attacks:
            for info in self._attacks.values():
                self._terminate_procs(info["procs"])
            self._attacks.clear()

    def do_EOF(self, line):
        self._cleanup()
        return super().do_EOF(line)

    def do_exit(self, line):
        self._cleanup()
        return super().do_exit(line)

    def do_quit(self, line):
        self._cleanup()
        return super().do_quit(line)


# ---------------------------------------------------------------------------
# Nodo router Linux
# ---------------------------------------------------------------------------

class LinuxRouter(Node):

    def config(self, **params):
        super().config(**params)
        self.cmd('sysctl -w net.ipv4.ip_forward=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv4.ip_forward=0')
        super().terminate()


# ---------------------------------------------------------------------------
# Prompts interactivos
# ---------------------------------------------------------------------------

def _prompt_int(prompt: str, default: int, min_value: int = 1) -> int:
    while True:
        raw = input(f"{prompt} [{default}]: ").strip()
        if not raw:
            return default
        try:
            v = int(raw)
            if v >= min_value:
                return v
            print(f"  Debe ser >= {min_value}.")
        except ValueError:
            print("  Ingresa un número entero válido.")


def _ask_params(args) -> tuple:
    if args.switches and args.hosts:
        return args.switches, args.hosts

    print()
    print("=== Generador interactivo de topología árbol ===")
    print("  Router Linux en la raíz → switches OpenFlow → hosts")
    print()

    n_sw = args.switches or _prompt_int("Número de switches OpenFlow", default=2, min_value=1)
    n_h  = args.hosts    or _prompt_int("Número de hosts totales",     default=4, min_value=1)
    return n_sw, n_h


# ---------------------------------------------------------------------------
# Construcción de la topología
# ---------------------------------------------------------------------------

def build_topology(n_switches: int, n_hosts: int, refresh_interval: int):
    """
    Subredes:  10.0.{sw_num}.0/24   (sw_num: 1 … n_switches)
    Router:    10.0.{sw_num}.1      en cada switch
    Hosts:     10.0.{sw_num}.{10 + posición dentro del switch}
    Round-robin: host i (base-0) → switch (i % n_switches)
    """
    net = Mininet(controller=None, switch=OVSSwitch, link=TCLink)

    print("\n*** Agregando controlador remoto")
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)

    print(f"*** Agregando {n_switches} switch(es) OpenFlow")
    switches = [
        net.addSwitch(f's{i}', protocols='OpenFlow13')
        for i in range(1, n_switches + 1)
    ]

    print("*** Agregando router Linux")
    router = net.addHost('r1', cls=LinuxRouter, ip=None)

    hosts_per_switch    = [[] for _ in range(n_switches)]
    count_per_switch    = [0]  * n_switches

    print(f"*** Agregando {n_hosts} host(s) en round-robin")
    hosts = []
    for h_idx in range(n_hosts):
        sw_idx   = h_idx % n_switches
        sw_num   = sw_idx + 1
        h_num    = h_idx + 1
        host_pos = count_per_switch[sw_idx]
        host_ip  = f'10.0.{sw_num}.{10 + host_pos}/24'
        gw       = f'10.0.{sw_num}.1'

        h = net.addHost(f'h{h_num}', ip=host_ip, defaultRoute=f'via {gw}')
        hosts.append(h)
        hosts_per_switch[sw_idx].append((f'h{h_num}', host_ip))
        count_per_switch[sw_idx] += 1

    print("*** Conectando hosts a sus switches")
    for h_idx, h in enumerate(hosts):
        net.addLink(h, switches[h_idx % n_switches])

    print("*** Conectando router a cada switch")
    for sw in switches:
        net.addLink(router, sw)

    print("*** Iniciando la red")
    net.start()

    print("*** Configurando interfaces del router")
    for i in range(n_switches):
        sw_num = i + 1
        router.cmd(f'ip addr add 10.0.{sw_num}.1/24 dev r1-eth{i}')
        router.cmd(f'ip link set r1-eth{i} up')

    # Resumen
    print()
    print("=== Topología ===")
    print(f"  Switches : {n_switches}   Hosts : {n_hosts}")
    print()
    for i in range(n_switches):
        sw_num    = i + 1
        subnet    = f'10.0.{sw_num}.0/24'
        gw        = f'10.0.{sw_num}.1'
        host_list = ', '.join(
            f"{name}({ip.split('/')[0]})" for name, ip in hosts_per_switch[i]
        ) or "(sin hosts)"
        print(f"  s{sw_num}  {subnet:18s}  gw {gw}  →  {host_list}")
    print()
    print("  Rutas del router:")
    print(router.cmd('ip route'))

    # Tráfico de fondo
    mgr = NormalTrafficManager(net, refresh_interval=refresh_interval)
    if len(hosts) >= 2:
        print(f"*** Iniciando tráfico de fondo aleatorio "
              f"({len(hosts)} flujos, rota cada {refresh_interval}s)")
        mgr.start()
    else:
        print("*** Solo hay 1 host — tráfico de fondo desactivado.")

    print()
    print("  Comandos disponibles en la CLI:")
    print("    attack       — lanza un ataque DDoS (menú interactivo)")
    print("    stopattack   — detiene todos los ataques (o stopattack <id>)")
    print("    listattacks  — muestra ataques activos")
    print("    startnormal  — reanuda el tráfico de fondo")
    print("    stopnormal   — pausa el tráfico de fondo")
    print("    listnormal   — muestra los flujos de fondo activos")
    print()

    return net, mgr


# ---------------------------------------------------------------------------
# Punto de entrada
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Topología árbol Mininet con tráfico base y lanzador de ataques DDoS"
    )
    parser.add_argument('--switches', type=int, default=0,
                        help='Número de switches OpenFlow (0 = interactivo)')
    parser.add_argument('--hosts', type=int, default=0,
                        help='Número de hosts totales (0 = interactivo)')
    parser.add_argument('--refresh', type=int, default=60,
                        help='Segundos entre rotaciones del tráfico de fondo (default: 60)')
    args = parser.parse_args()

    setLogLevel('warning')

    n_switches, n_hosts = _ask_params(args)

    if n_switches < 1 or n_hosts < 1:
        print("Error: se necesita al menos 1 switch y 1 host.", file=sys.stderr)
        sys.exit(1)

    net, mgr = build_topology(n_switches, n_hosts, args.refresh)

    AttackCLI(net, normal_mgr=mgr)
    net.stop()


if __name__ == '__main__':
    main()
