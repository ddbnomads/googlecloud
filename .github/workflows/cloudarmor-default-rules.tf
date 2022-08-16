terraform {
  required_providers {
    google = {
      source = "hashicorp/google-beta"
      version = "4.29.0"
    }
  }
}

provider "google" {
  # Configuration options
}

resource "google_compute_security_policy" "policy" {
  name = "infrastructure-as-code-security-policy"
  description = "template rules"
  
  advanced_options_config {
      json_parsing = "STANDARD"
      log_level= "VERBOSE"
  }
    type = "CLOUD_ARMOR"

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
    action   = "throttle"
    priority = "3000"
    preview = true
    rate_limit_options {
          enforce_on_key = "ALL"
          conform_action = "allow"
          exceed_action = "deny(429)"
          rate_limit_threshold {
              count = "100"
              interval_sec = "60" 
          }
      }
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    description = "Rate limit all user IPs"
  }
   
   rule {
    action   = "allow"
    priority = "5000"
    preview = true
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["2.2.2.0/24"]
      }
    }
    description = "Allow access to IPs in specific CIDR"
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
    action   = "deny(403)"
    priority = "10000"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('php-v33-stable')"
      }
    }
    description = "PHP - OWASP Rule"
  }

  rule {
    action   = "deny(403)"
    priority = "11000"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sqli-v33-stable')"
      }
    }
    description = "SQLi - OWASP Rule"
  }

  rule {
    action   = "deny(403)"
    priority = "12000"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('xss-v33-stable')"
      }
    }
    description = "XSS - OWASP Rule"
  }

  rule {
    action   = "deny(403)"
    priority = "13000"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('lfi-v33-stable')"
      }
    }
    description = "LFI - OWASP Rule"
  }

rule {
    action   = "deny(403)"
    priority = "14000"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rfi-v33-stable')"
      }
    }
    description = "RFI - OWASP Rule"
  }

  rule {
    action   = "deny(403)"
    priority = "15000"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('rce-v33-stable')"
      }
    }
    description = "RCE - OWASP Rule"
  }

  rule {
    action   = "deny(403)"
    priority = "16000"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('methodenforcement-v33-stable')"
      }
    }
    description = "Method Enforcement - OWASP Rule"
  }

  rule {
    action   = "deny(403)"
    priority = "17000"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('scannerdetection-v33-stable')"
      }
    }
    description = "Scanner Detection - OWASP Rule"
  }

rule {
    action   = "deny(403)"
    priority = "18000"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('protocolattack-v33-stable')"
      }
    }
    description = "Protocol Attack - OWASP Rule"
  }

  rule {
    action   = "deny(403)"
    priority = "19000"
    match {
      expr {
        expression = "evaluatePreconfiguredExpr('sessionfixation-v33-stable')"
      }
    }
    description = "Session Fixation - OWASP Rule"
  }
rule {
   action   = "deny(403)"
   priority = "20000"
   match {
     expr {
       expression = "evaluatePreconfiguredExpr('nodejs-v33-stable')"
     }
   }
   description = "Node.js - OWASP Rule"
 }

rule {
   action   = "deny(403)"
   priority = "21000"
   match {
     expr {
       expression = "evaluatePreconfiguredExpr('java-v33-stable')"
     }
   }
   description = "Java - OWASP Rule"
 }

 rule {
   action   = "deny(403)"
   priority = "22000"
   match {
     expr {
       expression = "evaluatePreconfiguredExpr('cve-canary')"
     }
   }
   description = "Critical vulnerabilities rule"
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
