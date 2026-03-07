provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

variable "project_id" {
  description = "The GCP project ID."
  type        = string
}

variable "region" {
  description = "The GCP region."
  type        = string
  default     = "us-central1"
}

module "cloud_armor" {
  source = "../../"

  project_id          = var.project_id
  name                = "advanced-security-policy"
  description         = "Advanced Cloud Armor policy with rate limiting, geo-blocking, and WAF"
  default_rule_action = "allow"

  advanced_options_config = {
    json_parsing = "STANDARD"
    log_level    = "VERBOSE"
  }

  rules = [
    # IP denylist
    {
      action      = "deny(403)"
      priority    = 1000
      description = "Block known malicious IPs"
      match = {
        versioned_expr = "SRC_IPS_V1"
        config = {
          src_ip_ranges = ["192.0.2.0/24", "198.51.100.0/24"]
        }
      }
    },
    # Geo-blocking
    {
      action      = "deny(403)"
      priority    = 2000
      description = "Block traffic from restricted countries"
      match = {
        expr = {
          expression = "origin.region_code == 'CN' || origin.region_code == 'RU' || origin.region_code == 'KP'"
        }
      }
    },
    # Rate limiting
    {
      action      = "throttle"
      priority    = 3000
      description = "Rate limit API requests to 100 per minute per IP"
      match = {
        expr = {
          expression = "request.path.matches('/api/.*')"
        }
      }
      rate_limit_options = {
        conform_action = "allow"
        exceed_action  = "deny(429)"
        enforce_on_key = "IP"
        rate_limit_threshold = {
          count        = 100
          interval_sec = 60
        }
      }
    },
    # Rate-based ban for login endpoint
    {
      action      = "rate_based_ban"
      priority    = 3100
      description = "Ban IPs making excessive login attempts"
      match = {
        expr = {
          expression = "request.path.matches('/auth/login')"
        }
      }
      rate_limit_options = {
        conform_action = "allow"
        exceed_action  = "deny(403)"
        enforce_on_key = "IP"
        rate_limit_threshold = {
          count        = 10
          interval_sec = 60
        }
        ban_threshold = {
          count        = 50
          interval_sec = 300
        }
        ban_duration_sec = 3600
      }
    }
  ]

  # WAF rules
  pre_configured_waf_rules = [
    {
      action            = "deny(403)"
      priority          = 5000
      description       = "SQL injection protection"
      preview           = true
      rule_set          = "sqli-v33-stable"
      sensitivity_level = 2
    },
    {
      action            = "deny(403)"
      priority          = 5100
      description       = "Cross-site scripting protection"
      preview           = true
      rule_set          = "xss-v33-stable"
      sensitivity_level = 2
    },
    {
      action            = "deny(403)"
      priority          = 5200
      description       = "Local file inclusion protection"
      preview           = true
      rule_set          = "lfi-v33-stable"
      sensitivity_level = 1
    }
  ]
}

output "policy_name" {
  description = "The security policy name."
  value       = module.cloud_armor.policy_name
}

output "policy_self_link" {
  description = "The security policy self link."
  value       = module.cloud_armor.policy_self_link
}

output "rule_count" {
  description = "Total number of rules."
  value       = module.cloud_armor.rule_count
}
