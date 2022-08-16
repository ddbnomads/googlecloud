#terraform {
#  required_providers {
#    google = {
#      source = "hashicorp/google"
#      version = "4.28.0"
#    }
#  }
#}

#provider "google" {
  # Configuration options
#}

resource "google_compute_security_policy" "edgepolicy" {
  name = "edge-security-policy"
  description = "edge rules"
  type = "CLOUD_ARMOR_EDGE"

  rule {
    action   = "deny(403)"
    priority = "1000"
    preview = true
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["9.9.9.0/24"]
      }
    }
    description = "Deny access to specific IP addresses"
  }

   rule {
    action   = "deny(403)"
    priority = "7000"
    preview = true
    match {
      expr {
        expression = "origin.region_code == 'CN' && origin.region_code == 'RU'"
      }
    }
    description = "Block users from specific countries"
  }
rule {
    action   = "allow"
    priority = "2147483647"
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "default rule"
  }
  
}