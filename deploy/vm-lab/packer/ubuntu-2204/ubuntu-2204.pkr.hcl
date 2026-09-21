# ubuntu-2204.pkr.hcl -- golden template for every Ubuntu-based VM in the
# lab (suscriptor, br, ric, ran, ue, core5g -- see ../topology.yaml).
#
# Ubuntu Server 22.04.5 LTS specifically -- the exact version srsRAN
# Project's own application notes (gNB+RIC E2 interface, multi-UE ZMQ
# emulation) are written and validated against. Later 22.04.x point
# releases are binary-compatible; do not jump to 24.04 without re-checking
# srsRAN's own compatibility notes first.
#
# Usage:
#   packer init .
#   packer build -var-file=vars.pkrvars.hcl ubuntu-2204.pkr.hcl

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
variable "iso_datastore" {
  type    = string
  default = null # falls back to `datastore`
}
variable "ssh_password" {
  type      = string
  sensitive = true
  default   = "srslab-temp"
}

source "vsphere-iso" "ubuntu" {
  vcenter_server      = var.esxi_host
  username            = var.esxi_user
  password            = var.esxi_password
  insecure_connection = true
  host                = var.esxi_host
  datastore           = var.datastore

  vm_name       = "tpl-ubuntu-2204"
  guest_os_type = "ubuntu64Guest"
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

  iso_url      = "https://releases.ubuntu.com/22.04/ubuntu-22.04.5-live-server-amd64.iso"
  iso_checksum = "file:https://releases.ubuntu.com/22.04/SHA256SUMS"

  # Served over HTTP to the VM during boot -- subiquity's autoinstall reads
  # user-data/meta-data from this NoCloud datasource, so the whole OS
  # install (partitioning, user, ssh keys, package updates) needs zero
  # interactive input.
  http_directory = "http"

  boot_wait = "5s"
  boot_command = [
    "<esc><wait>",
    "e<wait>",
    "<down><down><down><end>",
    " autoinstall ds=nocloud-net\\;s=http://{{.HTTPIP}}:{{.HTTPPort}}/ ---<f10>"
  ]

  ssh_username         = "labadmin"
  ssh_password         = var.ssh_password
  ssh_timeout          = "40m"
  shutdown_command     = "sudo shutdown -P now"
  shutdown_timeout     = "5m"
}

build {
  sources = ["source.vsphere-iso.ubuntu"]

  provisioner "shell" {
    inline = [
      "sudo apt-get update -qq",
      "sudo apt-get install -y -qq qemu-guest-agent cloud-init python3",
      "sudo cloud-init clean --logs",
      # Regenerate machine-id at first real boot of every CLONE, not just
      # this template -- otherwise all 6 Ubuntu VMs share one machine-id
      # and DHCP/cloud-init identity gets confused.
      "sudo truncate -s 0 /etc/machine-id",
      "sudo rm -f /var/lib/dbus/machine-id"
    ]
  }
}
