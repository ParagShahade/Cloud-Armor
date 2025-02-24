# Cloud Armor Security Policy Terraform Configuration

## Overview
This Terraform module sets up **Google Cloud Armor** security policies to protect your infrastructure from common web application attacks, such as **SQL Injection, XSS, and DDoS attacks**. It also configures a **backend service, health check, and IAM roles** for managing security policies.

## Features
- **Cloud Armor Security Policy** with predefined **Web Application Firewall (WAF) rules**
- **Region-based traffic filtering** (e.g., allowing only traffic from Germany and blocking other regions)
- **IP-based blocking** for specific IP ranges
- **DDoS protection** enabled by default
- **Service Account** with necessary IAM roles to manage security policies
- **Backend service** attached to the security policy
- **Health check** configuration for backend service
- **Required APIs** enabled automatically

## Requirements
- Terraform v1.0+
- Google Cloud Platform (GCP) Project
- Permissions to create IAM roles, service accounts, and security policies

## Usage
### 1. Set up Terraform Variables
Update the following variables in your Terraform configuration:
```hcl
variable "project_id" {
  description = "The GCP Project ID"
  type        = string
}
```

### 2. Initialize and Apply Terraform
Run the following commands:
```sh
terraform init
terraform plan
terraform apply -auto-approve
```

## Resources Created
### Service Account
- **sa-cloud-armor-waf**: Used for managing Cloud Armor policies
- Assigned IAM roles:
  - `roles/iam.serviceAccountAdmin`
  - `roles/compute.securityAdmin`
  - `roles/resourcemanager.projectIamAdmin`
  - `roles/serviceusage.serviceUsageAdmin`

### APIs Enabled
- Cloud Resource Manager API
- Compute Engine API
- IAM API
- IAM Credentials API
- Security Token Service API

### Security Policy
- **Rules to deny**
  - Traffic from Russia (`RU`)
  - Traffic from all regions except Germany (`DE`)
  - Common web attacks (**SQL Injection, XSS, LFI, RFI, RCE, etc.**)
  - Specific IP range: `192.168.100.0/24`
- **Default rule to allow all other traffic**
- **Adaptive DDoS protection enabled**

### Backend Service
- **Backend Service**: `waf-backend-service`
- **Health Check**: `/` on port `80`
- **Attached Security Policy**: `cloud-armor-waf-policy`

## Notes
- Modify the security rules as per your organizational requirements.
- Ensure the service account has the necessary permissions to manage security policies.
- Review firewall rules to ensure Cloud Armor functions correctly.

## Cleanup
To remove all resources created by this module, run:
```sh
terraform destroy -auto-approve
```
---
**Author**: Parag Shahade  

