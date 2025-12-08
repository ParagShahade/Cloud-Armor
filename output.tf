output "backend_service_name" {
  value = google_compute_backend_service.backend_service_waf.name
}

output "cloud_armor_policy_name" {
  value = google_compute_security_policy.cloud_armor_policy_waf.name
}
