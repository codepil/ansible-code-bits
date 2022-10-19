source "googlecompute" "rhel-7" {
  account_file = var.gcp_creds
  project_id = var.project_id

  source_image_family = "rhel-7"
  # Not including 'source_image name' attribute, will always picks the latest from the source_image_family
  zone = var.zone

  # resulting image attributes
  image_name = "rhel-7-v${formatdate("YYYYMMDDhhmm", timestamp())}-golden"
  image_description = "Red Hat   Golden Enterprise Linux 7: Base Image"
  # image family name should be different to from source_image_family name
  image_family = "gold-rhel-7"
  image_labels = {
      "os" = "rhel-7"
      "created_by" = "packer"
      "environment" = var.environment
      "commit_sha" = var.commit_sha
  }

  ssh_username = "packer"
  subnetwork = var.vm_subnet
  tags = local.vm_tags
  skip_create_image = var.skip_create_image
}



