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

variable "recaptcha_site_key" {
  description = "reCAPTCHA site key for bot management."
  type        = string
  default     = ""
}

module "cloud_armor" {
  source = "../../"

  project_id          = var.project_id
  name                = "complete-security-policy"
  description         = "Comprehensive Cloud Armor policy with all features enabled"
  type                = "CLOUD_ARMOR"
  default_rule_action = "deny(403)"

  # Adaptive Protection
  adaptive_protection_config = {
    enabled                              = true
    layer_7_ddos_defense_enable          = true
    layer_7_ddos_defense_rule_visibility = "STANDARD"
  }

  # Advanced options
  advanced_options_config = {
    json_parsing = "STANDARD"
    log_level    = "VERBOSE"
  }

  # reCAPTCHA (only if site key provided)
  recaptcha_options_config = var.recaptcha_site_key != "" ? {
    redirect_site_key = var.recaptcha_site_key
  } : null

  rules = [
    # Allowlist - internal/trusted IPs
    {
      action      = "allow"
      priority    = 100
      description = "Allow internal corporate network"
      match = {
        versioned_expr = "SRC_IPS_V1"
        config = {
          src_ip_ranges = ["10.0.0.0/8", "172.16.0.0/12"]
        }
      }
    },
    {
      action      = "allow"
      priority    = 200
      description = "Allow office and VPN IPs"
      match = {
        versioned_expr = "SRC_IPS_V1"
        config = {
          src_ip_ranges = ["203.0.113.0/24", "198.51.100.0/24"]
        }
      }
    },
    # Geo-blocking
    {
      action      = "deny(403)"
      priority    = 500
      description = "Block traffic from embargoed countries"
      match = {
        expr = {
          expression = "origin.region_code == 'KP' || origin.region_code == 'IR' || origin.region_code == 'SY' || origin.region_code == 'CU'"
        }
      }
    },
    # Allow specific countries
    {
      action      = "allow"
      priority    = 600
      description = "Allow traffic from authorized countries"
      match = {
        expr = {
          expression = "origin.region_code == 'US' || origin.region_code == 'CA' || origin.region_code == 'GB' || origin.region_code == 'DE' || origin.region_code == 'FR' || origin.region_code == 'AU'"
        }
      }
    },
    # Bot protection with custom header
    {
      action      = "allow"
      priority    = 700
      description = "Allow requests with valid API key header"
      match = {
        expr = {
          expression = "request.headers['x-api-key'] == 'trusted-partner-key'"
        }
      }
      header_action = {
        request_headers_to_adds = [
          {
            header_name  = "X-Cloud-Armor-Verified"
            header_value = "true"
          }
        ]
      }
    },
    # Rate limiting - global
    {
      action      = "throttle"
      priority    = 2000
      description = "Global rate limit: 1000 requests per minute per IP"
      match = {
        versioned_expr = "SRC_IPS_V1"
        config = {
          src_ip_ranges = ["*"]
        }
      }
      rate_limit_options = {
        conform_action = "allow"
        exceed_action  = "deny(429)"
        enforce_on_key = "IP"
        rate_limit_threshold = {
          count        = 1000
          interval_sec = 60
        }
      }
    },
    # Rate limiting - API endpoints
    {
      action      = "throttle"
      priority    = 2100
      description = "API rate limit: 200 requests per minute per IP"
      match = {
        expr = {
          expression = "request.path.matches('/api/v[0-9]+/.*')"
        }
      }
      rate_limit_options = {
        conform_action = "allow"
        exceed_action  = "deny(429)"
        enforce_on_key = "IP"
        rate_limit_threshold = {
          count        = 200
          interval_sec = 60
        }
      }
    },
    # Rate-based ban for authentication endpoints
    {
      action      = "rate_based_ban"
      priority    = 2200
      description = "Ban IPs with excessive auth attempts"
      match = {
        expr = {
          expression = "request.path.matches('/auth/.*') || request.path.matches('/login')"
        }
      }
      rate_limit_options = {
        conform_action = "allow"
        exceed_action  = "deny(403)"
        enforce_on_key = "IP"
        rate_limit_threshold = {
          count        = 15
          interval_sec = 60
        }
        ban_threshold = {
          count        = 100
          interval_sec = 600
        }
        ban_duration_sec = 7200
      }
    },
    # Block common attack patterns
    {
      action      = "deny(403)"
      priority    = 3000
      description = "Block requests to sensitive paths"
      match = {
        expr = {
          expression = "request.path.matches('/\\.env') || request.path.matches('/wp-admin/.*') || request.path.matches('/\\.git/.*') || request.path.matches('/phpmyadmin/.*')"
        }
      }
    },
    # Block requests with suspicious user agents
    {
      action      = "deny(403)"
      priority    = 3100
      description = "Block known scanner user agents"
      match = {
        expr = {
          expression = "has(request.headers['user-agent']) && request.headers['user-agent'].matches('(?i)(sqlmap|nikto|nessus|masscan|zgrab)')"
        }
      }
    }
  ]

  # Comprehensive WAF rules
  pre_configured_waf_rules = [
    {
      action            = "deny(403)"
      priority          = 5000
      description       = "OWASP SQL Injection protection"
      preview           = false
      rule_set          = "sqli-v33-stable"
      sensitivity_level = 2
    },
    {
      action            = "deny(403)"
      priority          = 5100
      description       = "OWASP Cross-Site Scripting protection"
      preview           = false
      rule_set          = "xss-v33-stable"
      sensitivity_level = 2
    },
    {
      action            = "deny(403)"
      priority          = 5200
      description       = "OWASP Local File Inclusion protection"
      preview           = false
      rule_set          = "lfi-v33-stable"
      sensitivity_level = 1
    },
    {
      action            = "deny(403)"
      priority          = 5300
      description       = "OWASP Remote File Inclusion protection"
      preview           = false
      rule_set          = "rfi-v33-stable"
      sensitivity_level = 1
    },
    {
      action            = "deny(403)"
      priority          = 5400
      description       = "OWASP Remote Code Execution protection"
      preview           = false
      rule_set          = "rce-v33-stable"
      sensitivity_level = 1
    },
    {
      action            = "deny(403)"
      priority          = 5500
      description       = "Method enforcement"
      preview           = true
      rule_set          = "methodenforcement-v33-stable"
      sensitivity_level = 1
    },
    {
      action            = "deny(403)"
      priority          = 5600
      description       = "Scanner detection"
      preview           = true
      rule_set          = "scannerdetection-v33-stable"
      sensitivity_level = 1
    },
    {
      action            = "deny(403)"
      priority          = 5700
      description       = "Protocol attack protection"
      preview           = true
      rule_set          = "protocolattack-v33-stable"
      sensitivity_level = 1
    },
    {
      action            = "deny(403)"
      priority          = 5800
      description       = "Session fixation protection"
      preview           = true
      rule_set          = "sessionfixation-v33-stable"
      sensitivity_level = 1
    },
    {
      action            = "deny(403)"
      priority          = 5900
      description       = "Java-specific attack protection"
      preview           = true
      rule_set          = "java-v33-stable"
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

output "policy_id" {
  description = "The security policy ID."
  value       = module.cloud_armor.policy_id
}

output "rule_count" {
  description = "Total number of custom rules."
  value       = module.cloud_armor.rule_count
}
