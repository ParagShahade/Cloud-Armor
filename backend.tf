resource "google_compute_health_check" "waf_hck" {
  project = var.project_id

  name = "waf-health-check"

  http_health_check {
    request_path = "/"
    port         = 80
  }
}

resource "google_compute_backend_service" "backend_service_waf" {
  project = var.project_id

  name        = "waf-backend-service"
  description = "Backend service for Cloud Armor example"

  health_checks   = [google_compute_health_check.waf_hck.self_link]
  security_policy = google_compute_security_policy.cloud_armor_policy_waf.id
}

