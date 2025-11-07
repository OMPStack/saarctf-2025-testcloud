
# ------------------
# Variables
# ------------------
variable "hcloud_datacenter" {
  type      = string
  default   = "fsn1-dc14"
}

variable "cheapest_vm" {
  type    = string
  default = "cx23"
}

variable "default_os_image" {
  type    = string
  default = "ubuntu-24.04"
}

locals {
  hcloud_location = regex("^([a-z0-9]+)", var.hcloud_datacenter)[0]
}

resource "hcloud_ssh_key" "main" {
  name       = "main-ssh-key"
  public_key = file("~/.ssh/id_rsa.pub")
}

# ------------------
# Public IP addresses
# ------------------

resource "hcloud_primary_ip" "gateway_ip" {
  name          = "gateway-ip"
  datacenter    = var.hcloud_datacenter
  type          = "ipv4"
  assignee_type = "server"
  auto_delete   = false
}

resource "hcloud_primary_ip" "gateway_ip_v6" {
  name          = "gateway-ip-v6"
  datacenter    = var.hcloud_datacenter
  type          = "ipv6"
  assignee_type = "server"
  auto_delete   = false
}

resource "hcloud_primary_ip" "vulnbox_ip" {
  name          = "vulnbox-ip"
  datacenter    = var.hcloud_datacenter
  type          = "ipv4"
  assignee_type = "server"
  auto_delete   = false
}

resource "hcloud_primary_ip" "vulnbox_ip_v6" {
  name          = "vulnbox-ip-v6"
  datacenter    = var.hcloud_datacenter
  type          = "ipv6"
  assignee_type = "server"
  auto_delete   = false
}

# -------------------
# VMs
# -------------------

resource "hcloud_server" "vulnbox" {
  name        = "vulnbox"
  image       = var.default_os_image
  server_type = var.cheapest_vm
  location    = local.hcloud_location
  labels = {
    omp-server-type = "vulnbox"
  }

  ssh_keys = [hcloud_ssh_key.main.id]

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
    ipv4 = hcloud_primary_ip.vulnbox_ip.id
    ipv6 = hcloud_primary_ip.vulnbox_ip_v6.id
  }

  depends_on = [
    hcloud_primary_ip.vulnbox_ip,
    hcloud_primary_ip.vulnbox_ip_v6,
  ]
}

resource "hcloud_server" "gamegateway" {
  name        = "gamegateway"
  image       = var.default_os_image
  server_type = var.cheapest_vm
  location    = local.hcloud_location
  labels = {
    omp-server-type = "gamegateway"
  }

  ssh_keys = [hcloud_ssh_key.main.id]

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
    ipv4 = hcloud_primary_ip.gateway_ip.id
    ipv6 = hcloud_primary_ip.gateway_ip_v6.id
  }

  depends_on = [
    hcloud_primary_ip.gateway_ip,
    hcloud_primary_ip.gateway_ip_v6,
  ]
}

# ------------------
# Firewall
# ------------------

resource "hcloud_firewall" "vpn_router_fw" {
  name = "vpn-fw"

  rule {
    direction  = "in"
    protocol   = "udp"
    port       = "51821" # Vulnnet wireguard
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "22" # SSH
    source_ips = ["0.0.0.0/0", "::/0"]
  }

  apply_to {
    label_selector = "omp-server-type=gamegateway"
  }

  apply_to {
    label_selector = "omp-server-type=vulnbox"
  }
}

# ------------------
# DNS
# ------------------

variable "domain" {
  type = string
}

data "cloudflare_zone" "dns_zone" {
  filter = {
    name = var.domain
  }
}

locals {
  domain_zone_id = data.cloudflare_zone.dns_zone.zone_id
}

# gateway
variable "gateway_hostname" {
  type = string
}

resource "cloudflare_dns_record" "gateway_dns_entry" {
  zone_id = local.domain_zone_id
  name    = var.gateway_hostname
  type    = "A"
  content = hcloud_primary_ip.gateway_ip.ip_address
  ttl     = 60
  proxied = false
  depends_on = [hcloud_primary_ip.gateway_ip]
}

/*
resource "cloudflare_dns_record" "gateway_AAAA_dns_entry" {
  zone_id = local.domain_zone_id
  name    = var.gateway_hostname
  type    = "AAAA"
  content = hcloud_primary_ip.gateway_ip_v6.ip_address
  ttl     = 60
  proxied = false
  depends_on = [hcloud_server.gamegateway]
}
*/

# vulnbox
variable "vulnbox_hostname" {
  type = string
}

resource "cloudflare_dns_record" "vulnbox_dns_entry" {
  zone_id = local.domain_zone_id
  name    = var.vulnbox_hostname
  ttl     = 60
  type    = "A"
  proxied = false
  content = hcloud_primary_ip.vulnbox_ip.ip_address
  depends_on = [hcloud_primary_ip.vulnbox_ip]
}

/*
resource "cloudflare_dns_record" "vulnbox_AAAA_dns_entry" {
  zone_id = local.domain_zone_id
  name    = var.vulnbox_hostname
  type    = "AAAA"
  content = hcloud_primary_ip.vulnbox_ip_v6.ip_address
  ttl     = 60
  proxied = false
  depends_on = [hcloud_server.vulnbox]
}
*/