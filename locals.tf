locals {
  # Build WAF rule expressions
  waf_rule_expressions = {
    for rule in var.pre_configured_waf_rules :
    rule.priority => length(rule.opt_out_rule_ids) > 0 ? (
      "evaluatePreconfiguredWaf('${rule.rule_set}', {'sensitivity': ${rule.sensitivity_level}, 'opt_out_rule_ids': [${join(",", [for id in rule.opt_out_rule_ids : "'${id}'"])}]})"
    ) : (
      "evaluatePreconfiguredWaf('${rule.rule_set}', {'sensitivity': ${rule.sensitivity_level}})"
    )
  }

  # Determine if adaptive protection should be configured
  enable_adaptive_protection = var.adaptive_protection_config.enabled

  # All rule priorities including WAF rules for conflict detection
  all_priorities = concat(
    [for rule in var.rules : rule.priority],
    [for rule in var.pre_configured_waf_rules : rule.priority]
  )
}
