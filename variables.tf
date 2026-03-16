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
  description = "The type of the security policy (CLOUD_ARMOR, CLOUD_ARMOR_EDGE, CLOUD_ARMOR_NETWORK)."
  type        = string
  default     = "CLOUD_ARMOR"

  validation {
    condition     = contains(["CLOUD_ARMOR", "CLOUD_ARMOR_EDGE", "CLOUD_ARMOR_NETWORK"], var.type)
    error_message = "Type must be one of: CLOUD_ARMOR, CLOUD_ARMOR_EDGE, CLOUD_ARMOR_NETWORK."
  }
}

variable "adaptive_protection_config" {
  description = "Adaptive Protection configuration with DDoS defense settings."
  type = object({
    enabled                             = optional(bool, false)
    layer_7_ddos_defense_enable         = optional(bool, false)
    layer_7_ddos_defense_rule_visibility = optional(string, "STANDARD")
  })
  default = {
    enabled = false
  }
}

variable "advanced_options_config" {
  description = "Advanced options for JSON parsing and log level."
  type = object({
    json_parsing = optional(string, "DISABLED")
    log_level    = optional(string, "NORMAL")
  })
  default = null
}

variable "recaptcha_options_config" {
  description = "reCAPTCHA options with redirect site key."
  type = object({
    redirect_site_key = string
  })
  default = null
}

variable "default_rule_action" {
  description = "Action for the default rule (allow, deny(403), deny(404), deny(502))."
  type        = string
  default     = "allow"

  validation {
    condition     = contains(["allow", "deny(403)", "deny(404)", "deny(502)"], var.default_rule_action)
    error_message = "Default rule action must be one of: allow, deny(403), deny(404), deny(502)."
  }
}

variable "rules" {
  description = "List of security policy rules with action, priority, match, and optional rate limiting."
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
      conform_action      = optional(string, "allow")
      exceed_action       = optional(string, "deny(403)")
      enforce_on_key      = optional(string, "IP")
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
  description = "List of pre-configured WAF rules with rule_set, sensitivity_level, and opt_out_rule_ids."
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
