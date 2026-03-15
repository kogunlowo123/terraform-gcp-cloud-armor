module "test" {
  source = "../"

  project_id  = "test-project-id"
  name        = "test-security-policy"
  description = "Test Cloud Armor security policy"
  type        = "CLOUD_ARMOR"

  default_rule_action = "allow"

  adaptive_protection_config = {
    enabled                     = true
    layer_7_ddos_defense_enable = true
  }

  rules = [
    {
      action      = "deny(403)"
      priority    = 1000
      description = "Block traffic from known bad IP ranges"
      preview     = false
      match = {
        versioned_expr = "SRC_IPS_V1"
        config = {
          src_ip_ranges = ["192.0.2.0/24", "198.51.100.0/24"]
        }
      }
    },
    {
      action      = "throttle"
      priority    = 2000
      description = "Rate limit all traffic"
      preview     = true
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
          count        = 100
          interval_sec = 60
        }
      }
    }
  ]

  pre_configured_waf_rules = [
    {
      action            = "deny(403)"
      priority          = 3000
      description       = "SQL injection protection"
      preview           = true
      rule_set          = "sqli-v33-stable"
      sensitivity_level = 2
    },
    {
      action            = "deny(403)"
      priority          = 3001
      description       = "Cross-site scripting protection"
      preview           = true
      rule_set          = "xss-v33-stable"
      sensitivity_level = 1
    }
  ]
}
