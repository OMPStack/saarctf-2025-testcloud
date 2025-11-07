terraform {
  required_providers {
    hcloud = {
      source  = "hetznercloud/hcloud"
      version = ">= 1.45.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5"
    }
  }
}

provider "hcloud" {
  # automatically reads from HCLOUD_TOKEN env variable
}

provider "cloudflare" {
  # automatically reads from CLOUDFLARE_API_TOKEN env variable
}