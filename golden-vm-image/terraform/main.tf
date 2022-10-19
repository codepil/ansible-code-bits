terraform {
  required_version = ">= 0.13"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 3.44.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 1.13.3"
    }
  }
}

data "google_project" "project" {
  project_id    = var.image_project_id
}

data "google_service_account" "image_automation" {
  /*
    SA account associated with existing Workload Identity
  */
  account_id  = var.image_project_id
  project     = var.automation_project_id
}

resource "google_project_iam_member" "image_automation" {
  for_each = toset(local.image_packer_automation_additive_roles)
  project  = data.google_project.project.project_id
  role     = each.value
  member   = "serviceAccount:${data.google_service_account.image_automation.email}"
}

resource "google_service_account" "packer" {
  project      = data.google_project.project.project_id
  account_id   = "${data.google_project.project.project_id}-i"
  display_name = "Packer Service Account (Terraform managed)"
  description  = "Packer account for ${data.google_project.project.project_id}"
}

resource "google_project_iam_member" "packer" {
  for_each = toset(local.packer_sa_roles)
  project  = data.google_project.project.project_id
  role     = each.value
  member   = "serviceAccount:${google_service_account.packer.email}"
}

resource "google_storage_bucket" "image_packer_automation_bucket" {
  project       = var.automation_project_id
  name          = "${data.google_project.project.project_id}-state-pkr"
  force_destroy = var.allow_destroy
  location      = "US"
  versioning {
    enabled = true
  }
}

resource "google_storage_bucket_iam_member" "image_packer_automation_bucket" {
  bucket = google_storage_bucket.image_packer_automation_bucket.name
  role   = "roles/storage.admin"
  member = "serviceAccount:${data.google_service_account.image_automation.email}"
}

resource "google_compute_subnetwork" "subnet_for_packer_vms" {
  name          = "subnet-for-packer-vms"
  ip_cidr_range = "10.2.0.0/16"
  region        = "us-east1"
  network       = google_compute_network.image_vpc.id
  project       = data.google_project.project.project_id
}

resource "google_compute_network" "image_vpc" {
  name      = "image-vpc"
  project   = data.google_project.project.project_id
}

resource "google_compute_firewall" "packer-fw-rule" {
  name        = "packer-fw-rule"
  description = "Specialized firewall rule to allow SSH and WinRm connection from a specific IP range where Packer is running to ${data.google_project.project.project_id}"
  network     = google_compute_network.image_vpc.name
  project     = data.google_project.project.project_id

  allow {
    protocol = "tcp"
    ports    = ["22", "5986"]
  }

  target_tags = toset([local.packerTag])
  source_ranges = toset(var.packer_source_project_ip_range)
}

resource "google_compute_firewall" "packer-updates" {
  name        = "packer-updates"
  description = "Allow images being built by packer to access the internet for patches and configurations."
  network     = google_compute_network.image_vpc.name
  project     = data.google_project.project.project_id
  direction   = "EGRESS"
  allow {
    protocol = "tcp"
    ports    = ["80", "443"]
  }

  target_tags = toset([local.packerTag])
  destination_ranges = ["0.0.0.0/0"]
}

# resource "google_compute_firewall" "debug-rule" {
#   name        = "debug-rule"
#   description = "Debug rule to allow image creation connectivity"
#   network     = google_compute_network.image_vpc.name
#   project     = data.google_project.project.project_id

#   allow {
#     protocol = "tcp"
#     ports    = ["3389"]
#   }

#   target_tags   = toset([local.packerTag])
#   source_ranges = ["0.0.0.0/0"]
# }
