# Export the service account email
output "service_account_email" {
  value = google_service_account.cloud_armor_service_account.email
}

output "backend_service_name" {
  value = google_compute_backend_service.backend_service_waf.name
}

output "cloud_armor_policy_name" {
  value = google_compute_security_policy.cloud_armor_policy_waf.name
}
