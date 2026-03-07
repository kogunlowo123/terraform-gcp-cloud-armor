provider "google" {
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
  name                = "basic-security-policy"
  description         = "Basic Cloud Armor security policy with IP controls"
  default_rule_action = "allow"

  rules = [
    {
      action      = "deny(403)"
      priority    = 1000
      description = "Block known malicious IP ranges"
      match = {
        versioned_expr = "SRC_IPS_V1"
        config = {
          src_ip_ranges = ["192.0.2.0/24", "198.51.100.0/24"]
        }
      }
    },
    {
      action      = "allow"
      priority    = 900
      description = "Allow office IP ranges"
      match = {
        versioned_expr = "SRC_IPS_V1"
        config = {
          src_ip_ranges = ["203.0.113.0/24"]
        }
      }
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
