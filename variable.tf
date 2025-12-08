variable "project_id" {
  description = "GCP project ID where resources will be created."
  type        = string
}

variable "region" {
  description = "Default region for regional resources."
  type        = string
  default     = "europe-west1"
}