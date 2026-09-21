# VLAN_BACKBONE: separar gestión OOB del tráfico de usuario/ataque

Estado: **implementado y confirmado funcionando de punta a punta en los 4 dominios**
(mobile, broadband, peering, enterprise), probado desde un cliente real de cada
uno (no solo desde el nodo de agregación) hacia `victim`. Automatizado en
`playbooks/test_vlan_backbone.yml`. Fecha: 2026-09-21.

## 1. Motivación

Antes de este trabajo, tres de los cuatro dominios usaban la interfaz de
**gestión** (MGMT, `10.10.0.0/24` — la red que Ansible/SSH usan para administrar
las VMs) como salida de facto para su propio tráfico de usuario/ataque hacia
`victim`:

- **`core5g`**: enmascaraba (`MASQUERADE`) el pool de IPs de UE (`10.45.0.0/16`)
  hacia afuera por `ens160`, su propia interfaz de MGMT.
- **`bng`**: reenviaba el tráfico de suscriptores directo entre BB_ACCESS y su
  propia interfaz de MGMT, sin NAT.
- **`peer-router`/`br`**: ni siquiera existía un camino hacia `victim` en
  absoluto desde este dominio antes de este trabajo.

Solo el dominio **enterprise** (`ent-site-N` → `pe` → `victim`) ya estaba limpio,
gracias al bridge OVS de 2 puertos de `pe` construido en un trabajo anterior.

## 2. Diseño

**VLAN_BACKBONE no es una sola red compartida** — es `pe` actuando como switch
real de 5 puertos (antes 2), con un enlace punto a punto dedicado por dominio:

```
        core5g ──10.91.0.0/30── pe ──10.55.0.0/24── victim
           │                    │  \
    (RAN, F1, N2/N3)      10.70.0.0/24  10.93.0.0/30
           │              (ENT_LAN)         │
          ran/du/ue    ent-site-1..5       br ──10.30.0.0/29── peer-router
                                            │
                                       (BGP real)
                    bng ──10.92.0.0/30── pe
                     │
              (BB_ACCESS)
                     │
                suscriptor
```

`pe` sigue siendo un **bridge L2 puro** (`br-ent`, controlado por OpenFlow desde
`orchestrator`/ryu-manager) — nunca hace routing L3. La interfaz ENT_DC de `pe`
y `victim` (antes exclusiva del dominio enterprise) ahora hace **doble función**
como el tramo final común del backbone: los otros 3 dominios convergen ahí
también.

### 2.1. Por qué 3 enlaces punto a punto y no un segmento compartido

La primera idea (reutilizar ENT_DC como una sola red plana, agregando
`core5g`/`bng`/`br` al mismo portgroup) se descartó a propósito: si esas 3 VMs
compartieran el mismo segmento L2 de ESXi que `pe`/`victim`, su tráfico
**no tendría por qué pasar por el bridge de `pe`** para llegar a `victim` — serían
vecinos L2 directos a nivel de vSwitch, exactamente el mismo bug que ya se
había encontrado y arreglado una vez para ENT_LAN/ENT_DC (ver
`docs/ran-testing.md`, no — ver el propio comentario de `ENT_DC` en
`topology.yaml`: sin el 2º puerto, el tráfico de `ent-site-N` tenía un camino
que rodeaba `pe` por completo, invisible para `ryu-manager`).

Por eso cada dominio tiene su **propio portgroup ESXi dedicado**
(`VLAN-BACKBONE-MOBILE`/`FIXED`/`PEERING`), compartido únicamente entre `pe` y
esa VM — la única forma de salir de ese portgroup es a través del bridge de
`pe`, igual que ya pasa con ENT_LAN.

### 2.2. NAT vs. ruta real: distinto por dominio, a propósito

| Dominio | Mecanismo | Por qué |
|---|---|---|
| Mobile (`core5g`) | `MASQUERADE` | El pool de UE (`10.45.0.0/16`) no necesita ser visible más allá de `core5g` — igual que antes, solo cambió la interfaz de salida. |
| Broadband (`bng`) | `MASQUERADE` | Mismo razonamiento — la identidad del suscriptor ya se resuelve en `bng` (FreeRADIUS), no hace falta preservar su IP real más allá. |
| Peering (`br`) | **Sin NAT**, ruta real + BGP | El dominio peering depende de ver la IP origen real/spoofeada para su propia lógica de detección (`config/settings.py`'s `PER_SOURCE_MITIGATION_DOMAINS`, y la reescritura allowlist→denylist documentada en `docs/peering-plan.md`). Enmascarar aquí rompería esa detección. |
| Enterprise (`pe`↔`ent-site`) | Sin NAT (ya existente) | Bridge L2 puro, sin cambios. |

Para el caso sin NAT (`br`), `victim` necesita una ruta **con gateway real**
(`via <IP de br en el backbone>`), no la ruta "sin gateway" que sí funciona para
los otros casos — porque `peer-router` no está en el mismo segmento del bridge
de `pe` (está detrás de `br`, que actúa como router IP real ahí). Ver
`roles/victim/tasks/main.yml`'s comentario sobre `peering_cidr`.

## 3. Direccionamiento

| Red | CIDR | Portgroup ESXi | Miembros |
|---|---|---|---|
| `BACKBONE_MOBILE` | `10.91.0.0/30` | `VLAN-BACKBONE-MOBILE` | `pe` (sin IP, bridge), `core5g` (`.2`) |
| `BACKBONE_FIXED` | `10.92.0.0/30` | `VLAN-BACKBONE-FIXED` | `pe` (sin IP, bridge), `bng` (`.2`) |
| `BACKBONE_PEERING` | `10.93.0.0/30` | `VLAN-BACKBONE-PEERING` | `pe` (sin IP, bridge), `br` (`.2`) |
| `ENT_DC` (reusada) | `10.55.0.0/24` | `VLAN-BACKBONE-ENTERPRISE` | `pe` (sin IP, bridge), `victim` (`.100`) |

`victim` **no recibió ninguna NIC nueva** — su interfaz ENT_DC ya existente pasó
a hacer doble función como cara del backbone.

## 4. Bugs reales encontrados construyendo esto

1. **La regla `MASQUERADE` vieja no se limpia sola.** Agregar la regla nueva
   (`-o <interfaz backbone>`) deja la vieja (`-o ens160`) activa en paralelo —
   ambas coexisten, el tráfico podía seguir teniendo un camino por MGMT sin que
   nadie lo notara. Hubo que agregar una tarea explícita de limpieza
   (`iptables -D ...`) en `core5g_open5gs`.

2. **Los portgroups nuevos necesitaban "promiscuous mode" habilitado**, igual
   que ENT_LAN/ENT_DC/BB_ACCESS ya lo tenían — sin esto, el ARP entre los dos
   lados del bridge de `pe` nunca resuelve, y el síntoma (`Destination Host
   Unreachable` generado localmente) parece un bug de ruteo cuando en realidad
   es el propio vSwitch de ESXi descartando frames no destinados a la MAC
   receptora antes de que OVS los vea. Automatizado ahora en
   `scripts/setup_portgroups.sh` vía el campo `promiscuous: true` de
   `topology.yaml`.

3. **`peer-router` tenía un filtro de importación BGP que descartaba la ruta
   nueva.** `bird.conf.j2` solo aceptaba `10.99.0.1/32` a propósito (diseño
   original, documentado). Hubo que extender el filtro (`import where net =
   10.99.0.1/32 || net = {{ ent_dc_cidr }}`).

4. **`victim` necesitaba una ruta con gateway real para el dominio peering**,
   distinta del patrón "sin gateway" que sí funciona para los otros 3 — ver
   §2.2.

5. **`bng_target_ip` (el group_var que alimenta tanto al agente de
   suscriptores real como el fallback de ping de las playbooks de RAN) seguía
   apuntando a la IP de MGMT vieja de `victim`.** Un solo cambio en
   `render_topology.py` (`net_ip(victim, ENT_DC)` en vez de `mgmt_ip(victim)`)
   arregla el fallback en ambos dominios a la vez.

6. **Falso positivo de método de prueba:** `ping -I <interfaz>` (bind por
   dispositivo) y `ping -I <IP>` (bind por dirección) dan rutas **distintas**
   para el mismo destino cuando hay policy routing por IP origen (`ip rule`) de
   por medio — el software real de generación de tráfico
   (`bng_subscriber_agent.py`/`bng_flood.py`) usa bind por dirección. Probar
   con bind por dispositivo daba `Destination Host Unreachable` que parecía un
   bug del backbone y no lo era.

7. **Hallazgo no relacionado, mientras se investigaba lo anterior:** el
   portgroup `VLAN-ENT-DC` ya no existía con ese nombre en el ESXi real — en
   algún punto se renombró a `VLAN-BACKBONE-ENTERPRISE` (mismo VLAN ID, mismos
   2 puertos activos, nada de la conectividad cambió). `topology.yaml` se
   actualizó para reflejar el nombre real.

8. **Bug preexistente, no relacionado:** `br` tenía un `/etc/netplan/99-lab.yaml`
   desactualizado (gateway apuntando al gateway "arquitectónico" no funcional,
   sin `nameservers`) — bloqueaba `apt-get update`. Corregido a mano con el
   contenido ya generado correctamente.

## 5. Automatización

```bash
cd deploy/vm-lab
./scripts/setup_portgroups.sh              # crea/actualiza los portgroups ESXi
                                            # (idempotente, lee topology.yaml)
cd ansible
ansible-playbook site.yml --limit pe,core5g,bng,br,victim   # aplica los roles
ansible-playbook playbooks/test_vlan_backbone.yml           # prueba los 4 dominios
ansible-playbook playbooks/test_vlan_backbone.yml --tags peering,enterprise  # solo algunos
```

`test_vlan_backbone.yml` prueba desde un **cliente real** de cada dominio (no
el nodo de agregación): `ent-site-1`, `peer-router`, una sesión de `suscriptor`
con lease DHCP activo, y un UE atachado (requiere haber corrido
`test_split_cu_du.yml` antes — este playbook no maneja RACH/attach, solo
prueba conectividad).

**Confirmado en una corrida real:** 0% de pérdida en los 4 dominios,
simultáneamente, en una sola ejecución del playbook.
