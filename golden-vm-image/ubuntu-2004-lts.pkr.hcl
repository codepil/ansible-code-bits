source "googlecompute" "ubuntu-2004-lts" {
  account_file = var.gcp_creds
  project_id = var.project_id

  source_image_family = "ubuntu-2004-lts"
  # Not including 'source_image name' attribute, will always picks the latest from the source_image_family
  zone = var.zone

  #gcloud compute images list will give the image name, image project, family, status
  image_name = "ubuntu-2004-lts-v${formatdate("YYYYMMDDhhmm", timestamp())}-golden"
  image_description = "Golden Ubuntu 20.04: Base Image"
  # image family name should be different to from source_image_family name
  image_family = "gold-ubuntu-2004-lts"
  image_labels = {
      "os" = "ubuntu-2004-lts"
      "created_by" = "packer"
      "environment" = var.environment
      "commit_sha" = var.commit_sha
  }

  ssh_username = "packer"
  subnetwork = var.vm_subnet
  tags = local.vm_tags

  skip_create_image = var.skip_create_image
}

