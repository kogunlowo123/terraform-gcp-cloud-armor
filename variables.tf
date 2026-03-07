variable "project_id" {
  description = "The GCP project ID where the Cloud Armor security policy will be created."
  type        = string

  validation {
    condition     = length(var.project_id) > 0
    error_message = "Project ID must not be empty."
  }
}

variable "name" {
  description = "The name of the security policy."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,62}$", var.name))
    error_message = "Name must start with a lowercase letter, contain only lowercase letters, numbers, and hyphens, and be at most 63 characters."
  }
}

variable "description" {
  description = "Description of the security policy."
  type        = string
  default     = ""
}

variable "type" {
  description = "The type of the security policy. CLOUD_ARMOR for external HTTP(S) LB, CLOUD_ARMOR_EDGE for CDN, CLOUD_ARMOR_NETWORK for network LB."
  type        = string
  default     = "CLOUD_ARMOR"

  validation {
    condition     = contains(["CLOUD_ARMOR", "CLOUD_ARMOR_EDGE", "CLOUD_ARMOR_NETWORK"], var.type)
    error_message = "Type must be one of: CLOUD_ARMOR, CLOUD_ARMOR_EDGE, CLOUD_ARMOR_NETWORK."
  }
}

variable "adaptive_protection_config" {
  description = <<-EOT
    Adaptive Protection configuration:
    - enabled: Whether to enable Adaptive Protection.
    - layer_7_ddos_defense_enable: Enable Layer 7 DDoS defense.
    - layer_7_ddos_defense_rule_visibility: Visibility of auto-deployed rules (STANDARD or PREMIUM).
  EOT
  type = object({
    enabled                          = optional(bool, false)
    layer_7_ddos_defense_enable      = optional(bool, false)
    layer_7_ddos_defense_rule_visibility = optional(string, "STANDARD")
  })
  default = {
    enabled = false
  }
}

variable "advanced_options_config" {
  description = <<-EOT
    Advanced options configuration:
    - json_parsing: JSON parsing mode (DISABLED, STANDARD, STANDARD_WITH_GRAPHQL).
    - log_level: Logging level (NORMAL, VERBOSE).
  EOT
  type = object({
    json_parsing = optional(string, "DISABLED")
    log_level    = optional(string, "NORMAL")
  })
  default = null
}

variable "recaptcha_options_config" {
  description = <<-EOT
    reCAPTCHA options:
    - redirect_site_key: reCAPTCHA site key for redirect-based challenges.
  EOT
  type = object({
    redirect_site_key = string
  })
  default = null
}

variable "default_rule_action" {
  description = "Action for the default rule. Either 'allow' or 'deny(403)' or 'deny(404)' or 'deny(502)'."
  type        = string
  default     = "allow"

  validation {
    condition     = contains(["allow", "deny(403)", "deny(404)", "deny(502)"], var.default_rule_action)
    error_message = "Default rule action must be one of: allow, deny(403), deny(404), deny(502)."
  }
}

variable "rules" {
  description = <<-EOT
    List of security policy rules. Each rule contains:
    - action: allow, deny(403), deny(404), deny(502), redirect, throttle, rate_based_ban
    - priority: Rule priority (lower number = higher priority). Range: 0-2147483646.
    - description: Rule description.
    - preview: If true, the rule is in preview/logging-only mode.
    - match: Match configuration with:
      - versioned_expr: SRC_IPS_V1 for IP-based matching.
      - config: Configuration with src_ip_ranges list.
      - expr: CEL expression for advanced matching.
    - rate_limit_options: (Optional) Rate limiting configuration with:
      - conform_action: Action when rate is not exceeded (allow).
      - exceed_action: Action when rate is exceeded (deny(403), deny(404), deny(502), redirect).
      - enforce_on_key: Key to rate limit on (ALL, IP, HTTP_HEADER, XFF_IP, HTTP_COOKIE, HTTP_PATH, SNI, REGION_CODE).
      - enforce_on_key_name: Name of the key (for HTTP_HEADER or HTTP_COOKIE).
      - rate_limit_threshold: count and interval_sec.
      - ban_threshold: (Optional) count and interval_sec for banning.
      - ban_duration_sec: Duration of ban in seconds.
    - redirect_options: (Optional) Redirect configuration with type (EXTERNAL_302, GOOGLE_RECAPTCHA) and target.
    - header_action: (Optional) Custom headers to add with request_headers_to_adds list.
  EOT
  type = list(object({
    action      = string
    priority    = number
    description = optional(string, "")
    preview     = optional(bool, false)
    match = object({
      versioned_expr = optional(string)
      config = optional(object({
        src_ip_ranges = list(string)
      }))
      expr = optional(object({
        expression = string
      }))
    })
    rate_limit_options = optional(object({
      conform_action    = optional(string, "allow")
      exceed_action     = optional(string, "deny(403)")
      enforce_on_key    = optional(string, "IP")
      enforce_on_key_name = optional(string)
      rate_limit_threshold = object({
        count        = number
        interval_sec = number
      })
      ban_threshold = optional(object({
        count        = number
        interval_sec = number
      }))
      ban_duration_sec = optional(number)
    }))
    redirect_options = optional(object({
      type   = string
      target = optional(string)
    }))
    header_action = optional(object({
      request_headers_to_adds = list(object({
        header_name  = string
        header_value = string
      }))
    }))
  }))
  default = []

  validation {
    condition = alltrue([
      for rule in var.rules : rule.priority >= 0 && rule.priority <= 2147483646
    ])
    error_message = "Rule priorities must be between 0 and 2147483646."
  }
}

variable "pre_configured_waf_rules" {
  description = <<-EOT
    List of pre-configured WAF rules to add. Each contains:
    - action: allow, deny(403), deny(404), deny(502)
    - priority: Rule priority.
    - description: Rule description.
    - preview: Preview mode.
    - rule_set: The pre-configured WAF rule set (e.g., sqli-v33-stable, xss-v33-stable, lfi-v33-stable, rfi-v33-stable, rce-v33-stable, methodenforcement-v33-stable, scannerdetection-v33-stable, protocolattack-v33-stable, php-v33-stable, sessionfixation-v33-stable, java-v33-stable, nodejs-v33-stable, cve-canary).
    - sensitivity_level: Sensitivity level (0-4). Lower = fewer false positives.
    - opt_out_rule_ids: List of rule IDs to exclude from the rule set.
  EOT
  type = list(object({
    action            = string
    priority          = number
    description       = optional(string, "")
    preview           = optional(bool, true)
    rule_set          = string
    sensitivity_level = optional(number, 1)
    opt_out_rule_ids  = optional(list(string), [])
  }))
  default = []
}

variable "backend_services" {
  description = "List of backend service self_links to attach this security policy to."
  type        = list(string)
  default     = []
}
