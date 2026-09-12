# debian-13.pkr.hcl -- golden template for the orchestrator VM
# (ryu-manager + exabgp, see ../topology.yaml). Only one VM uses this
# template, but it's kept as its own golden image (not just cloned ad hoc)
# so re-provisioning the orchestrator from scratch is as reproducible as
# every other VM in the lab.

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

source "vsphere-iso" "debian" {
  vcenter_server      = var.esxi_host
  username            = var.esxi_user
  password            = var.esxi_password
  insecure_connection = true
  host                = var.esxi_host
  datastore           = var.datastore

  vm_name       = "tpl-debian-13"
  guest_os_type = "debian12_64Guest"  # ESXi's guest-id list lags Debian's own
                                       # numbering; 12_64Guest is the closest
                                       # match and works fine for Debian 13.
  CPUs          = 2
  RAM           = 2048
  firmware      = "efi"

  disk_controller_type = ["pvscsi"]
  storage {
    disk_size             = 10240
    disk_thin_provisioned = true
  }
  network_adapters {
    network      = var.network
    network_card = "vmxnet3"
  }

  iso_url      = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/debian-13.6.0-amd64-netinst.iso"
  iso_checksum = "https://cdimage.debian.org/debian-cd/current/amd64/iso-cd/SHA256SUMS"

  http_directory = "http/debian"

  boot_wait = "5s"
  boot_command = [
    "<esc><wait>",
    "install ",
    "auto=true priority=critical ",
    "url=http://{{.HTTPIP}}:{{.HTTPPort}}/preseed.cfg ",
    "<enter>"
  ]

  ssh_username     = "labadmin"
  ssh_password     = var.ssh_password
  ssh_timeout      = "40m"
  shutdown_command = "sudo shutdown -P now"
  shutdown_timeout = "5m"
}

build {
  sources = ["source.vsphere-iso.debian"]

  provisioner "shell" {
    inline = [
      "sudo apt-get update -qq",
      "sudo apt-get install -y -qq open-vm-tools cloud-init python3 python3-pip python3-venv git curl",
      "sudo cloud-init clean --logs",
      "sudo truncate -s 0 /etc/machine-id",
      "sudo rm -f /var/lib/dbus/machine-id"
    ]
  }
}
