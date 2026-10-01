# VM lab -- 23-VM ESXi topology

Automates standing up the "topología con límites de VM, interfaces y
puntos de medición reales" the thesis review asked for: 4 domains
(enterprise, mobile, broadband, bgp/peering), one real VM per functional
element, sized to actually cross `DIST_MIN_SOURCES=5` per domain with
traffic honest to each domain's own design (spoofed only where the
domain already spoofs -- mobile, bgp -- never in enterprise).

**Status: verified against a real ESXi 7.0.3 host (Enterprise Plus
licensed, standalone, no vCenter).** The govc-based VM lifecycle
(register/resize/network/power) and every VM clone (Ubuntu/Debian/
Alpine) are confirmed working end-to-end on real hardware. Packer and
`govc vm.clone` were NOT usable at all -- see "Confirmed standalone-ESXi
limitations" below, a load-bearing section, read it before doing
anything else.

The mobile domain's full RIC/RAN/Core/UE chain (Open5GS, srsRAN Project
CU/DU, srsUE, O-RAN SC RIC) is confirmed working end-to-end against real
hardware: UE attach (RACH->RRC->PDU Session), real UL/DL traffic, E2SM-
KPM delivery with per-UE attribution, and RC-based mitigation (throttle/
release) all observed on real runs across all 5 UEs. It is NOT claimed
to be fully stable/deterministic -- the ZMQ RACH between a DU and its UE
is a known, unresolved source of non-determinism (see "Known risk
areas" #1 and the mobile-bringup-order-style bring-up this lab's own
`reconnect_mobile_domain.yml` automates), so a bring-up or a statistical
trial can still need a retry. "Works end-to-end" and "is stable under
repeated cycling" are different claims -- see
`analysis/README-statistical-trials.md`'s own repeatability campaign
(`--repeatability-cycles`) for how this repo actually measures the
second one, instead of assuming a single successful run proves it.

## Confirmed standalone-ESXi limitations (read this first)

Three separate vCenter-only restrictions were hit and confirmed on a
real host -- none are bugs in this repo's scripts, all are hard platform
limits with no config workaround:

1. **No REST/vAPI session auth.** `/rest/com/vmware/cis/session` and
   `/api/session` both return an empty `400 Bad Request` on a bare ESXi
   host, confirmed via plain `curl`, independent of Packer. CIS session
   management is fundamentally an SSO/PSC (vCenter) concept a standalone
   host doesn't implement the same way, regardless of license tier
   (confirmed against a real **Enterprise Plus** license -- this is not
   a "buy the free tier a license" problem). Packer's `vsphere-iso`
   builder hard-requires this login with no way to skip it
   (`packer-plugin-vsphere`'s `NewDriver()` always calls it) -- **Packer
   cannot build anything against standalone ESXi, period.**
2. **No `MarkAsTemplate`.** Confirmed via `govc vm.markastemplate`:
   `ServerFaultCode: The operation is not supported on the object.`
   Templates as a distinct object type from a VM are a vCenter inventory
   feature. Not needed anyway -- `vm.clone`/manual copying works from any
   powered-off VM regardless of template status.
3. **No `CloneVM_Task`.** Confirmed via `govc vm.clone`: the same "not
   supported on the object" error. Confirmed independently by a
   `govmomi` maintainer: *"ESXi does not support the `CloneVM` method,
   regardless of license. Only supported by vCenter."*
   (github.com/vmware/govmomi/issues/1469#issuecomment).

**What this means practically:**
- The 3 golden templates (`tpl-ubuntu-2204`, `tpl-debian-13`,
  `tpl-alpine`) must be built **by hand**, once each, via the ESXi web
  console (`https://<esxi-host>/ui/`) -- upload the ISO, `govc vm.create`
  the shell (scripted, see below), install interactively through the
  console. Not automatable without vCenter.
- `deploy_govc.sh` clones the 23 lab VMs via the standard bare-ESXi
  workaround instead of `vm.clone`: SSH to the ESXi host's own shell,
  `vmkfstools -i` to copy the VMDK at the datastore level, then
  `govc vm.register` the copy as a new VM. This means the script needs
  **SSH access to the ESXi host itself** (`TSM-SSH` service, check with
  `govc host.service.ls | grep ssh`), not just the vSphere API.
- Alpine clones can't be customized over SSH the way Ubuntu/Debian's
  cloud-init can -- a clone boots with the template's old hostname/IP,
  and there's no DHCP on these new internal VLANs to reach it any other
  way. `generated/alpine/<vm>/apply.sh` (see `scripts/render_topology.py`)
  has the fix -- paste it into the VM's **web console**, not SSH. It is
  deliberately NOT a re-run of `setup-alpine`: that tries to redo the
  *entire* install (repartition, re-download every base package), which
  both fails outright (no internet on a brand-new isolated VLAN yet) and
  is unnecessary -- the cloned disk already has everything installed.
  `apply.sh` only edits `/etc/hostname` and `/etc/network/interfaces`.

**Also confirmed necessary, not ESXi-specific:** whichever machine
actually runs `ansible-playbook`/`deploy_govc.sh` (the "control node")
needs its own IP address on **every one of the 5 lab VLANs**, not just
the one hosting the orchestrator -- otherwise most of the 23 VMs are
simply unreachable for configuration. If the control node is itself a VM
on the same ESXi host, give it one additional vNIC per VLAN
(`govc vm.network.add -vm <control-vm> -net <portgroup> -net.adapter vmxnet3`,
repeated 5x) and a static IP in each -- this is a one-time setup step on
the control node itself, not something `deploy_govc.sh` does for you.

## Layout

```
topology.yaml              # SINGLE SOURCE OF TRUTH -- 23 VMs, specs, addressing
packer/                    # 3 golden-image templates, ONE SUBDIRECTORY EACH
  ubuntu-2204/, debian-13/, alpine/   # (packer combines all .pkr.hcl in one dir into one template)
scripts/
  render_topology.py       # topology.yaml -> generated/ (cloud-init, answerfiles, Ansible inventory)
  deploy_govc.sh            # generated/ -> actual VMs on ESXi, via govc
ansible/
  site.yml, ansible.cfg
  roles/<role>/             # one role per topology.yaml `role:` value (13 roles, 23 VMs)
generated/                  # ALL derived from topology.yaml -- never hand-edit, re-run render_topology.py instead
```

## Prerequisites

- A standalone ESXi host with 5 port groups already created, matching
  `topology.yaml`'s `networks:` block, and **SSH enabled** (`TSM-SSH`
  service -- `govc host.service.ls | grep ssh`; enable via the DCUI or
  web UI if off). Check the exact port group names/subnets any time with:
  ```bash
  python3 scripts/render_topology.py   # first, to populate generated/
  ./scripts/deploy_govc.sh --portgroups
  ```
- [govc](https://github.com/vmware/govmomi/releases) (VMware's official
  CLI -- talks directly to ESXi, no vCenter required)
- `sshpass` (`apt install sshpass`) -- for non-interactive SSH to the
  ESXi host's own shell (`vmkfstools` has no vSphere API equivalent)
- Python 3 + `pip install -r requirements.txt` (pyyaml, ansible-core)
- `ansible-galaxy collection install community.general ansible.posix`
  (needed for the Alpine `apk` module and the sysctl module)
- ~~Packer~~ -- **not usable against standalone ESXi at all**, see
  above. The 3 golden templates are built by hand instead (step 2 below).

## Deployment flow

```bash
# 1. Generate everything derived from topology.yaml
python3 scripts/render_topology.py

export GOVC_URL="https://YOUR_ESXI_IP/sdk"
export GOVC_USERNAME=root GOVC_PASSWORD='YOUR_PASSWORD' GOVC_INSECURE=1
export GOVC_DATASTORE=YOUR_DATASTORE
export ESXI_HOST=YOUR_ESXI_IP ESXI_SSH_PASSWORD='YOUR_PASSWORD'

# 2. Build the 3 golden templates BY HAND (once each) -- Packer cannot do
#    this against standalone ESXi (see above). For each template
#    (tpl-alpine, tpl-ubuntu-2204, tpl-debian-13):
#      a) Upload its ISO to the datastore:
govc datastore.mkdir -p /isos
govc datastore.upload /path/to/the.iso isos/the.iso
#      b) Create the VM shell and attach the ISO:
govc vm.create -on=false -c=1 -m=512 -disk=2G -net="VM Network" \
               -net.adapter=vmxnet3 -g=other5xLinux64Guest tpl-alpine
govc device.cdrom.add -vm tpl-alpine
govc device.cdrom.insert -vm tpl-alpine -device cdrom-3000 isos/the.iso
govc vm.power -on tpl-alpine
#      c) Open https://YOUR_ESXI_IP/ui/ -> that VM -> Console, and
#         install interactively (Alpine: root/no password -> setup-alpine,
#         DHCP + openssh + PermitRootLogin yes; Ubuntu/Debian: normal
#         installer, create a `labadmin` user with sudo, install
#         openssh-server). When done, from the console:
#           echo "PermitRootLogin yes" >> /etc/ssh/sshd_config  # Alpine
#         then shut the VM down and eject its ISO:
govc device.cdrom.eject -vm tpl-alpine

# 3. Provision the 23 lab VMs (SSH+vmkfstools clone, resize, network,
#    cloud-init injection -- see deploy_govc.sh's own header for exactly
#    what this does and why it's not govc vm.clone)
./scripts/deploy_govc.sh

# 4. Alpine VMs need hostname+static-IP applied by hand via the WEB
#    CONSOLE (not SSH -- no DHCP on these VLANs yet). deploy_govc.sh
#    tells you which ones at the end; for each, open its console and
#    paste the contents of:
cat generated/alpine/<vm-name>/apply.sh

# 5. Install and configure the real software on all 23
cd ansible
ansible-playbook site.yml
```

Re-run step 5 any time (idempotent); re-run step 1 any time
`topology.yaml` changes (resizing a VM, changing an IP) and re-apply
steps 3-5 for whatever changed. Step 2 only needs to happen once, ever,
per golden template.

## Known risk areas (read before you start troubleshooting blind)

Ranked by how likely they are to actually bite you, based on this
project's own history and what srsRAN's docs say about themselves:

1. **RAN ↔ 5G Core cross-VM reachability (`core5g_open5gs` /
   `ran_srsran` roles).** srsRAN's own multi-UE tutorial runs gNB and
   Open5GS on ONE PC, reaching the AMF at Docker's own internal bridge
   IP. This lab splits them across VMs -- `open5gs.env.j2`'s own comment
   explains the fix attempted (pointing `OPEN5GS_IP`/`UPF_ADVERTISE_IP`
   at a real, cross-VM-routable address) and why it might still need
   `network_mode: host` or a macvlan network in srsRAN's own
   `docker-compose.yml` to actually work. If the gNB can't reach the
   AMF, check raw connectivity to `core5g` on tcp/udp 38412 FIRST.

2. **Near-RT RIC: O-RAN SC RIC, the DEFINITIVE stack (`ric_oran_sc`
   role).** Two earlier RIC integrations were tried and abandoned before
   this one: (a) `deploy/setup_ns_oran_flexric.sh`, ns-3 simulation +
   Orange's `ns-O-RAN-flexric` fork -- confirmed real bugs in that fork
   (a heap buffer overflow in ASN.1 measurement-name encoding,
   `bad_any_cast`, PRB-threshold gating), all inside Orange's ns-3 code;
   (b) FlexRIC built from source (`br-flexric`@`1a3903a7`, then `dev`) --
   never got its KPM delivery reliably working against srsRAN Project's
   current E2SM-KPM encoder (see the oran-sc-ric-migration history for
   the full story). **O-RAN SC RIC** (`github.com/srsran/oran-sc-ric`,
   pinned to the commit `ric_oran_sc/tasks/main.yml` clones) is the
   stack this lab actually runs now, with KPM delivery and RC-based
   mitigation both confirmed working end-to-end against this lab's real
   DUs/UEs -- a single `docker compose up`, no from-source build. Two
   patches on top of the stock repo (both captured verbatim from the
   validated deployment into the role's own `files/`): the RC actuator
   xApp runs in its OWN container (`rc_actuator_runner`, its own IP) so
   its RMR listener doesn't collide with the KPM bridge xApp's; the
   routing table sends `RIC_CONTROL_ACK`/`FAILURE` there accordingly.
   `ansible-playbook site.yml` alone reaches this state from a bare VM --
   no manual setup, no tribal knowledge needed beyond this README.

3. **5 UEs via 5 dedicated DUs, not a GNU-Radio broker
   (`du_srsran`/`ue_srsue` roles).** An earlier design combined 3 UEs'
   uplink through srsRAN's own `multi_ue_scenario.grc` broker -- confirmed
   unreliable past 1 UE (a real, unsolved Msg3 CRC failure from the
   combiner not modeling per-UE timing/CFO offset; srsRAN's own docs call
   this pattern "not optimized, performant, or scalable" and srsUE's 5G
   support "maintenance only"). The current, validated design instead
   gives each UE its OWN dedicated DU (`du`/`du2`/`du3`/`du4`/`du5`, see
   `topology.yaml`) and its own ZMQ RF pair -- no RF combining at all, so
   the broker's own combiner bug doesn't apply. 3 of the 5 UEs run on the
   `ue` VM, the other 2 on `ue2` (a 2nd UE-hosting VM, added once 3
   srsue instances plus the GNU-Radio broker stopped fitting comfortably
   on one VM -- see `topology.yaml`'s own `ue`/`ue2` comments). `ran` is
   paired with `du`/`du2`/`du3` as their CU (cu1); `cu2` is a 2nd CU
   paired with `du4`/`du5`.

4. **`gnb_zmq.yaml.j2`'s exact schema.** Cloned from `srsRAN_Project`'s
   `main` branch (not a pinned tag) -- the YAML schema for `cell_cfg`/`e2`
   blocks does change across commits. The base RF/cell config fields are
   copied verbatim from srsRAN's own current tutorial; the `e2:` block
   was added by this role and its field names are NOT independently
   confirmed against your exact checked-out commit.

## Software/version summary (see ansible/roles/*/tasks/main.yml for exact commands)

| VM(s) | OS | Key software |
|---|---|---|
| orchestrator | Debian 13 | ryu-manager + exabgp, exact `requirements.txt` pins from this repo |
| bng | Ubuntu 22.04 | accel-ppp (real IPoE BRAS) + FreeRADIUS (real AAA/accounting) |
| suscriptor | Ubuntu 22.04 | per-subscriber macvlan DHCP sessions, kernel-socket SYN/UDP flood (`simulation/bng_flood.py` -- hping3 confirmed not to work over these interfaces) |
| br | Ubuntu 22.04 | flow 0.2.0, nfdump 1.7.4 (this repo's own installer), FRR (real eBGP) |
| peer-router | Alpine | hping3, bird2 (real eBGP) |
| ric | Ubuntu 22.04 | **O-RAN SC RIC** (`github.com/srsran/oran-sc-ric`, docker compose -- see "Known risk areas" #2) |
| core5g | Ubuntu 22.04 | Open5GS, dockerized via `srsRAN_Project/docker` |
| ran, cu2 | Ubuntu 22.04 | srsRAN Project gNB (CU-CP+CU-UP only, split from the DU), ZMQ RF, E2 enabled -- 2 CUs: `ran`=cu1 (du/du2/du3), `cu2` (du4/du5) |
| du, du2, du3, du4, du5 | Ubuntu 22.04 | srsRAN Project DU (split from the CU), ZMQ RF, E2 + RC enabled -- one dedicated DU per UE |
| ue, ue2 | Ubuntu 22.04 | srsRAN_4G `srsue` ×5 total across network namespaces (`ue`: ue1-3, `ue2`: ue4-5) -- see "Known risk areas" #3 |
| pe | Alpine | Open vSwitch, OpenFlow13 to the orchestrator |
| ent-site-1..5 | Alpine | hping3, nftables (unspoofed real attack sources) |
| victim | Alpine | Python `http.server` |

## AS numbers

`topology.yaml`'s `bgp:` block: `br_as=65000`, `peer_router_as=64512` --
deliberately distinct from `FLOW_LOCAL_AS`/`EXABGP_LOCAL_AS` (65001/65002,
see `webtool/peering_ops.py`), which stay reserved for the *internal*
`flow`↔`exabgp` FlowSpec control channel. This lab's `br`↔`peer-router`
session is a separate, real eBGP session for genuine route exchange.
