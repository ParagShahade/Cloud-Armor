locals {

  # Roles to be assigned to the Cloud Armor Service Account at the Project level
  ca_sa_project_roles = [
    "roles/iam.serviceAccountAdmin",
    "roles/compute.securityAdmin",
    "roles/resourcemanager.projectIamAdmin",
    "roles/serviceusage.serviceUsageAdmin",

    # Additional roles depending on your needs
    # "roles/bigquery.admin",
    # "roles/aiplatform.admin",
    # "roles/compute.admin",
  ]
}

