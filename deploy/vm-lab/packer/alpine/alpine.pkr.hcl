# alpine.pkr.hcl -- golden template for the 7 lightweight-role VMs (bng,
# peer-router, pe, ent-site-1..5, victim -- see ../topology.yaml).
#
# Alpine's live ISO has no SSH/network config out of the box, so unlike
# the Ubuntu/Debian templates (which have real unattended-install
# datasources), this types shell commands directly at the console via
# boot_command to fetch the answerfile and drive `setup-alpine`
# non-interactively -- the standard community pattern for Alpine+Packer,
# since Alpine ships no autoinstall/preseed equivalent of its own.

packer {
  required_plugins {
    vsphere = {
      version = ">= 1.2.0"
      source  = "github.com/hashicorp/vsphere"
    }
  }
}

variable "esxi_host" {
  type = string
}
variable "esxi_user" {
  type    = string
  default = "root"
}
variable "esxi_password" {
  type      = string
  sensitive = true
}
variable "datastore" {
  type = string
}
variable "network" {
  type    = string
  default = "VM Network"
}
variable "ssh_password" {
  type      = string
  sensitive = true
  default   = "srslab-temp"
}

source "vsphere-iso" "alpine" {
  vcenter_server      = var.esxi_host
  username            = var.esxi_user
  password            = var.esxi_password
  insecure_connection = true
  host                = var.esxi_host
  datastore           = var.datastore

  vm_name       = "tpl-alpine"
  guest_os_type = "other5xLinux64Guest"
  CPUs          = 1
  RAM           = 512   # only for the build itself; topology.yaml sizes the clones
  firmware      = "bios"

  disk_controller_type = ["pvscsi"]
  storage {
    disk_size             = 2048
    disk_thin_provisioned = true
  }
  network_adapters {
    network      = var.network
    network_card = "vmxnet3"
  }

  iso_url      = "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-virt-3.24.1-x86_64.iso"
  iso_checksum = "https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/alpine-virt-3.24.1-x86_64.iso.sha256"

  http_directory = "http"

  boot_wait = "30s"
  boot_command = [
    "root<enter><wait2s>",
    # DHCP just for the build (topology.yaml's static IPs are applied per-VM
    # later, by scripts/render_topology.py's generated answerfile/cloud-init
    # at CLONE time -- this template itself stays network-agnostic).
    "udhcpc -i eth0<enter><wait5s>",
    "wget http://{{.HTTPIP}}:{{.HTTPPort}}/answerfile -O /tmp/answerfile<enter><wait2s>",
    "echo 'srslab-temp' | setup-alpine -f /tmp/answerfile<enter><wait30s>",
    "<enter><wait5s>",  # setup-alpine's own final "installation complete, reboot?" prompt
    "echo \"PermitRootLogin yes\" >> /etc/ssh/sshd_config<enter>",
    "rc-service sshd restart<enter><wait2s>"
  ]

  ssh_username     = "root"
  ssh_password     = var.ssh_password
  ssh_timeout      = "20m"
  shutdown_command = "poweroff"
  shutdown_timeout = "3m"
}

build {
  sources = ["source.vsphere-iso.alpine"]

  provisioner "shell" {
    inline = [
      "apk update",
      "apk add --no-cache open-vm-tools python3",
      "rc-update add open-vm-tools default",
      # Alpine has no machine-id by default (uses /var/lib/dbus/machine-id
      # only if dbus is installed, which it isn't here) -- nothing to reset.
      "rm -f /etc/ssh/ssh_host_*"  # regenerated fresh on each clone's first boot
    ]
  }
}
