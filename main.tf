
# Cloud Armor security policy
resource "google_compute_security_policy" "cloud_armor_policy_waf" {
  name        = "cloud-armor-waf-policy"
  description = "Cloud Armor security policy with WAF rules"
  project     = var.project_id

  dynamic "rule" {
    for_each = [
      # CVE-2025-55182 protection
      {
        description = "CVE-2025-55182 protection using cve-canary"
        priority    = 999
        expression  = <<-EOT
          (has(request.headers['next-action']) ||
           has(request.headers['rsc-action-id']) ||
           request.headers['content-type'].contains('multipart/form-data') ||
           request.headers['content-type'].contains('application/x-www-form-urlencoded'))
           && evaluatePreconfiguredWaf('cve-canary',{
             'sensitivity': 0,
             'opt_in_rule_ids': [
               'google-mrs-v202512-id000001-rce',
               'google-mrs-v202512-id000002-rce'
             ]
           })
        EOT
        action      = "deny(403)"
      },
      # Modsecurity
      {
        description = "SQL Injection protection"
        priority    = 1000
        expression  = "evaluatePreconfiguredWaf('sqli-v33-stable')"
        action      = "deny(403)"
      },
      {
        description = "Cross-Site Scripting (XSS) protection"
        priority    = 1001
        expression  = "evaluatePreconfiguredWaf('xss-v33-stable')"
        action      = "deny(403)"
      },
      {
        description = "Local File Inclusion (LFI) protection"
        priority    = 1002
        expression  = "evaluatePreconfiguredWaf('lfi-v33-stable')"
        action      = "deny(403)"
      },
      {
        description = "Remote File Inclusion (RFI) protection"
        priority    = 1003
        expression  = "evaluatePreconfiguredWaf('rfi-v33-stable')"
        action      = "deny(403)"
      },
      {
        description = "Remote Code Execution (RCE) protection"
        priority    = 1004
        expression  = "evaluatePreconfiguredWaf('rce-v33-stable')"
        action      = "deny(403)"
      },
      {
        description = "Method Enforcement"
        priority    = 1005
        expression  = "evaluatePreconfiguredWaf('methodenforcement-v33-stable')"
        action      = "deny(403)"
      },
      {
        description = "Scanner Detection"
        priority    = 1006
        expression  = "evaluatePreconfiguredWaf('scannerdetection-v33-stable')"
        action      = "deny(403)"
      },
      {
        description = "Protocol Attack"
        priority    = 1007
        expression  = "evaluatePreconfiguredWaf('protocolattack-v33-stable')"
        action      = "deny(403)"
      },
      {
        description = "PHP Injection Attack"
        priority    = 1008
        expression  = "evaluatePreconfiguredWaf('php-v33-stable')"
        action      = "deny(403)"
      },
      {
        description = "Session Fixation Attack"
        priority    = 1009
        expression  = "evaluatePreconfiguredWaf('sessionfixation-v33-stable')"
        action      = "deny(403)"
      },
      {
        description = "Java Attack"
        priority    = 1010
        expression  = "evaluatePreconfiguredWaf('java-v33-stable')"
        action      = "deny(403)"
      },
      {
        description = "NodeJS Attack"
        priority    = 1011
        expression  = "evaluatePreconfiguredWaf('nodejs-v33-stable')"
        action      = "deny(403)"
      }
    ]

    content {
      description = rule.value.description
      priority    = rule.value.priority
      match {
        expr {
          expression = rule.value.expression
        }
      }
      action = rule.value.action
    }
  }

  # IP-based rule for blocking specific IP range
  rule {
    description = "Block 192.168.100.0/24"
    priority    = 500
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["192.168.100.0/24"]
      }
    }
    action = "deny(403)"
  }

  # Sets up a Cloud Armor security policy along with DDoS protection enabled by default
  adaptive_protection_config {
    layer_7_ddos_defense_config {
      enable = true
    }
  }

  # Default rule to allow all other traffic
  rule {
    description = "Default rule"
    priority    = 2147483647
    match {
      versioned_expr = "SRC_IPS_V1"
      config {
        src_ip_ranges = ["*"]
      }
    }
    action = "allow"
  }
}
