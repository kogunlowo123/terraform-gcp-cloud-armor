output "policy_id" {
  description = "The ID of the security policy."
  value       = google_compute_security_policy.this.id
}

output "policy_name" {
  description = "The name of the security policy."
  value       = google_compute_security_policy.this.name
}

output "policy_self_link" {
  description = "The self link of the security policy."
  value       = google_compute_security_policy.this.self_link
}

output "policy_fingerprint" {
  description = "Fingerprint of the security policy."
  value       = google_compute_security_policy.this.fingerprint
}

output "policy_type" {
  description = "The type of the security policy."
  value       = google_compute_security_policy.this.type
}

output "rule_count" {
  description = "Total number of custom rules (excluding default rule)."
  value       = length(var.rules) + length(var.pre_configured_waf_rules)
}
