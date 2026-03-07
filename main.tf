###############################################################################
# Cloud Armor Security Policy
###############################################################################
resource "google_compute_security_policy" "this" {
  provider = google-beta

  project     = var.project_id
  name        = var.name
  description = var.description
  type        = var.type

  # Default rule (required, lowest priority)
  rule {
    action   = var.default_rule_action
    priority = 2147483647

    description = "Default rule"

    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
  }

  # Custom rules
  dynamic "rule" {
    for_each = var.rules
    content {
      action      = rule.value.action
      priority    = rule.value.priority
      description = rule.value.description
      preview     = rule.value.preview

      match {
        versioned_expr = rule.value.match.versioned_expr

        dynamic "config" {
          for_each = rule.value.match.config != null ? [rule.value.match.config] : []
          content {
            src_ip_ranges = config.value.src_ip_ranges
          }
        }

        dynamic "expr" {
          for_each = rule.value.match.expr != null ? [rule.value.match.expr] : []
          content {
            expression = expr.value.expression
          }
        }
      }

      dynamic "rate_limit_options" {
        for_each = rule.value.rate_limit_options != null ? [rule.value.rate_limit_options] : []
        content {
          conform_action      = rate_limit_options.value.conform_action
          exceed_action       = rate_limit_options.value.exceed_action
          enforce_on_key      = rate_limit_options.value.enforce_on_key
          enforce_on_key_name = rate_limit_options.value.enforce_on_key_name

          rate_limit_threshold {
            count        = rate_limit_options.value.rate_limit_threshold.count
            interval_sec = rate_limit_options.value.rate_limit_threshold.interval_sec
          }

          dynamic "ban_threshold" {
            for_each = rate_limit_options.value.ban_threshold != null ? [rate_limit_options.value.ban_threshold] : []
            content {
              count        = ban_threshold.value.count
              interval_sec = ban_threshold.value.interval_sec
            }
          }

          ban_duration_sec = rate_limit_options.value.ban_duration_sec
        }
      }

      dynamic "redirect_options" {
        for_each = rule.value.redirect_options != null ? [rule.value.redirect_options] : []
        content {
          type   = redirect_options.value.type
          target = redirect_options.value.target
        }
      }

      dynamic "header_action" {
        for_each = rule.value.header_action != null ? [rule.value.header_action] : []
        content {
          dynamic "request_headers_to_adds" {
            for_each = header_action.value.request_headers_to_adds
            content {
              header_name  = request_headers_to_adds.value.header_name
              header_value = request_headers_to_adds.value.header_value
            }
          }
        }
      }
    }
  }

  # Pre-configured WAF rules
  dynamic "rule" {
    for_each = var.pre_configured_waf_rules
    content {
      action      = rule.value.action
      priority    = rule.value.priority
      description = rule.value.description
      preview     = rule.value.preview

      match {
        expr {
          expression = local.waf_rule_expressions[rule.value.priority]
        }
      }
    }
  }

  # Adaptive Protection
  dynamic "adaptive_protection_config" {
    for_each = local.enable_adaptive_protection ? [1] : []
    content {
      layer_7_ddos_defense_config {
        enable          = var.adaptive_protection_config.layer_7_ddos_defense_enable
        rule_visibility = var.adaptive_protection_config.layer_7_ddos_defense_rule_visibility
      }
    }
  }

  # Advanced options
  dynamic "advanced_options_config" {
    for_each = var.advanced_options_config != null ? [var.advanced_options_config] : []
    content {
      json_parsing = advanced_options_config.value.json_parsing
      log_level    = advanced_options_config.value.log_level
    }
  }

  # reCAPTCHA options
  dynamic "recaptcha_options_config" {
    for_each = var.recaptcha_options_config != null ? [var.recaptcha_options_config] : []
    content {
      redirect_site_key = recaptcha_options_config.value.redirect_site_key
    }
  }
}

###############################################################################
# Backend Service Binding
###############################################################################
resource "google_compute_backend_service" "binding" {
  for_each = toset(var.backend_services)

  project         = var.project_id
  name            = element(split("/", each.value), length(split("/", each.value)) - 1)
  security_policy = google_compute_security_policy.this.self_link

  lifecycle {
    ignore_changes = [
      backend,
      health_checks,
      protocol,
      port_name,
      timeout_sec,
      description,
      enable_cdn,
      log_config,
    ]
  }
}
