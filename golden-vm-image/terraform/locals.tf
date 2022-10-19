locals {
  image_packer_automation_additive_roles = [
    # Packer additionally needed roles
    "roles/iam.serviceAccountKeyAdmin",
  ]

  packer_sa_roles = [
    # Packer needed roles
    "roles/compute.instanceAdmin.v1",
    "roles/iam.serviceAccountUser",
    "roles/secretmanager.secretAccessor",
  ]

  packerTag = "packer-vm"
}