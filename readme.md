# Cloud Armor WAF Example

Terraform configuration that provisions a Google Cloud Armor security policy (focused on the CVE-2025-55182 canary rule), a backend service, and a health check. Required APIs are enabled automatically.

## Prerequisites
- Terraform >= 1.5.0
- Google Cloud project with billing enabled
- Credentials (ADC or service account key) with permissions to create the listed resources

## Configuration
Variables (defaults are set in `variable.tf`):
- `project_id` — target GCP project
- `region` — default region for regional resources (default: `europe-west1`)


## Usage
```bash
terraform init
terraform plan
terraform apply
```

## Files
- `provider.tf` — provider config and versions
- `variable.tf` — project_id, region
- `apis.tf` — required API enablement
- `data.tf` — project data source
- `backend.tf` — health check and backend service
- `main.tf` — Cloud Armor security policy (CVE-2025-55182 rule, IP block, default allow)
- `locals.tf` — (currently unused placeholder)
- `output.tf` — key outputs (backend service, policy names)

## Resources Created
- Cloud Armor security policy `cloud-armor-waf-policy`
  - Deny rule using `evaluatePreconfiguredWaf('cve-canary')` for CVE-2025-55182
  - IP deny rule for `192.168.100.0/24`
  - Default allow rule
  - Adaptive L7 DDoS protection enabled
- Backend service `waf-backend-service` with attached policy
- HTTP health check on `/` port `80`
- Required Google APIs enabled for the project

## Cleanup
```bash
terraform destroy
```

