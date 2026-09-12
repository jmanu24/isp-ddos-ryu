# VM lab -- 16-VM ESXi topology (docs/thesis-revision-plan.md §4.1.1-4.1.2)

Automates standing up the "topología con límites de VM, interfaces y
puntos de medición reales" the thesis review asked for: 4 domains
(enterprise, mobile, broadband, bgp/peering), one real VM per functional
element, sized to actually cross `DIST_MIN_SOURCES=5` per domain with
traffic honest to each domain's own design (spoofed only where the
domain already spoofs -- mobile, bgp -- never in enterprise).

**Everything here is best-effort, unverified against a real ESXi host.**
No ESXi environment was available to test any of this end-to-end -- every
command/version/config is either (a) copied verbatim from this
project's own already-working scripts (`deploy/install_bgp_peering.sh`,
`deploy/install_bngblaster.sh`), or (b) fetched directly from srsRAN
Project's own official, current documentation (fetched live via `gh api`
against `srsran/srsRAN_Project_docs`, not from memory). Nothing was
invented and presented as fact -- where something is a genuine guess or
an extension beyond what's officially documented, it's flagged inline as
such (search for "NOT from the original docs", "unverified", "riskiest").
Budget real debugging time on your first run, especially for the
RIC/RAN/Core/UE stack (see "Known risk areas" below).

## Layout

```
topology.yaml              # SINGLE SOURCE OF TRUTH -- 16 VMs, specs, addressing
packer/                    # 3 golden-image templates, ONE SUBDIRECTORY EACH
  ubuntu-2204/, debian-13/, alpine/   # (packer combines all .pkr.hcl in one dir into one template)
scripts/
  render_topology.py       # topology.yaml -> generated/ (cloud-init, answerfiles, Ansible inventory)
  deploy_govc.sh            # generated/ -> actual VMs on ESXi, via govc
ansible/
  site.yml, ansible.cfg
  roles/<role>/             # one role per topology.yaml `role:` value (12 roles, 16 VMs)
generated/                  # ALL derived from topology.yaml -- never hand-edit, re-run render_topology.py instead
```

## Prerequisites

- A standalone ESXi host (no vCenter needed) with 5 port groups already
  created, matching `topology.yaml`'s `networks:` block. Check the exact
  names/subnets any time with:
  ```bash
  python3 scripts/render_topology.py   # first, to populate generated/
  ./scripts/deploy_govc.sh --portgroups
  ```
- [Packer](https://developer.hashicorp.com/packer/install) +
  `packer plugins install github.com/hashicorp/vsphere`
- [govc](https://github.com/vmware/govmomi/releases) (VMware's official
  CLI -- talks directly to ESXi, no vCenter required)
- Python 3 + `pip install -r requirements.txt` (pyyaml, ansible-core)
- `ansible-galaxy collection install community.general ansible.posix`
  (needed for the Alpine `apk` module and the sysctl module)

## Deployment flow

```bash
# 1. Generate everything derived from topology.yaml
python3 scripts/render_topology.py

# 2. Build the 3 golden templates (once) -- EACH LIVES IN ITS OWN
#    SUBDIRECTORY (packer/ubuntu-2204/, packer/debian-13/, packer/alpine/),
#    not the shared packer/ root -- `packer init .` combines every
#    .pkr.hcl file in one directory into a single template, so 3 files
#    declaring the same variable names in the same directory collide.
for t in ubuntu-2204 debian-13 alpine; do
  (
    cd "packer/$t"
    packer init .
    packer build -var esxi_host=YOUR_ESXI_IP -var esxi_password=YOUR_PASSWORD \
                  -var datastore=YOUR_DATASTORE "$t.pkr.hcl"
  )
done

# 3. Clone the 16 VMs from those templates, sized/networked per topology.yaml
export GOVC_URL="https://root:YOUR_PASSWORD@YOUR_ESXI_IP/sdk"
export GOVC_INSECURE=1
export GOVC_DATASTORE=YOUR_DATASTORE
./scripts/deploy_govc.sh

# 4. Alpine VMs (7 of them) need their static-IP answerfile applied by hand
#    after first boot -- deploy_govc.sh prints exactly which ones and reminds
#    you at the end. For each:
scp generated/alpine/<vm-name>/answerfile root@<temp-dhcp-ip>:/tmp/answerfile
ssh root@<temp-dhcp-ip> "setup-alpine -f /tmp/answerfile"

# 5. Install and configure the real software on all 16
cd ansible
ansible-playbook site.yml
```

Re-run step 5 any time (idempotent); re-run step 1 any time
`topology.yaml` changes (resizing a VM, changing an IP) and re-apply
steps 3-5 for whatever changed.

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

2. **Near-RT RIC / FlexRIC (`ric_flexric` role).** This project already
   tried and abandoned a DIFFERENT FlexRIC integration once
   (`deploy/setup_ns_oran_flexric.sh`, ns-3 simulation + Orange's
   `ns-O-RAN-flexric` fork on the `oie-ric-taap-xapps` branch) --
   confirmed real bugs in that fork (a heap buffer overflow in ASN.1
   measurement-name encoding, `bad_any_cast`, PRB-threshold gating), all
   inside Orange's ns-3 code, none in FlexRIC itself. This role uses a
   **different, official** path instead: FlexRIC's `br-flexric` branch
   (commit `1a3903a7`) against a **real srsRAN gNB's own native E2
   interface** -- confirmed via srsRAN Project's own current docs to be
   one of two officially-supported RIC integrations (the other being
   ORAN SC RIC, a single-`docker compose up` alternative if FlexRIC gives
   you trouble again -- see `ric_flexric`'s own task comments).

3. **5 UEs, not 3 (`ue_srsue` role).** The deployed
   `multi_ue_scenario.grc` GNU-Radio broker is srsRAN's own REAL,
   official file (fetched verbatim, not reconstructed) -- but it only
   wires up 3 UEs. Reaching 5 needs you to open it in
   `gnuradio-companion` and duplicate the UE3 signal path twice by hand
   (see the role's own final debug message) -- not something safe to
   hand-patch blind in raw XML. srsRAN's own docs also call this whole
   pattern "not optimized, performant, or scalable" and srsUE's 5G
   support "maintenance only, not for deployment-ready scenarios" -- budget
   real troubleshooting time here specifically.

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
| bng | Alpine | dnsmasq |
| suscriptor | Ubuntu 22.04 | BNGBlaster 0.9.17 (this repo's own installer) |
| br | Ubuntu 22.04 | flow 0.2.0, nfdump 1.7.4 (this repo's own installer), FRR (real eBGP) |
| peer-router | Alpine | hping3, bird2 (real eBGP) |
| ric | Ubuntu 22.04 | FlexRIC `br-flexric`@`1a3903a7` |
| core5g | Ubuntu 22.04 | Open5GS, dockerized via `srsRAN_Project/docker` |
| ran | Ubuntu 22.04 | srsRAN Project gNB, ZMQ RF, E2 enabled |
| ue | Ubuntu 22.04 | srsRAN_4G `srsue` ×5 (network namespaces) + GNU-Radio broker |
| pe | Alpine | Open vSwitch, OpenFlow13 to the orchestrator |
| ent-site-1..5 | Alpine | hping3, nftables (unspoofed real attack sources) |
| victim | Alpine | Python `http.server` |

## AS numbers

`topology.yaml`'s `bgp:` block: `br_as=65000`, `peer_router_as=64512` --
deliberately distinct from `FLOW_LOCAL_AS`/`EXABGP_LOCAL_AS` (65001/65002,
see `webtool/peering_ops.py`), which stay reserved for the *internal*
`flow`↔`exabgp` FlowSpec control channel. This lab's `br`↔`peer-router`
session is a separate, real eBGP session for genuine route exchange.
