# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-01-15

### Added

- Initial release of the Cloud Armor Terraform module.
- Security policy creation with CLOUD_ARMOR, CLOUD_ARMOR_EDGE, and CLOUD_ARMOR_NETWORK types.
- Custom rules with IP allowlist/denylist, geo-blocking, and CEL expressions.
- Rate limiting with configurable thresholds and ban durations.
- Rate-based ban with automatic banning on threshold breach.
- Pre-configured WAF rule sets (OWASP ModSecurity Core Rule Set).
- Adaptive Protection with Layer 7 DDoS defense.
- Advanced options for JSON parsing and verbose logging.
- reCAPTCHA integration for bot management.
- Redirect rules for external 302 and Google reCAPTCHA challenges.
- Backend service binding for automatic policy attachment.
- Comprehensive examples: basic, advanced, and complete.

## [0.1.0] - 2024-01-01

### Added

- Initial development version with core security policy functionality.
