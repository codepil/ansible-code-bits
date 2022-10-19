source "googlecompute" "windows-2019-core" {
  disk_size    = 50 // necessary for how big these images are
  communicator = "winrm"

  account_file   = var.gcp_creds
  project_id     = var.project_id
  winrm_username = "packer"
  winrm_insecure = true
  winrm_use_ssl  = true

  metadata = {
    windows-startup-script-cmd = "winrm quickconfig -quiet & net user /add packer & net localgroup administrators packer /add & winrm set winrm/config/service/auth @{Basic=\"true\"}"
  }
  machine_type        = "n1-standard-2"
  source_image_family = "windows-2019-core"
  zone                = var.zone

  image_name        = "windows-2019-core-v${formatdate("YYYYMMDDhhmm", timestamp())}-golden"
  image_description = "Golden Windows Server 2019 Core: Base Image"
  image_family      = "gold-windows-2019-core"
  image_labels = {
    "os"          = "windows-2019-core"
    "created_by"  = "packer"
    "environment" = var.environment
    "commit_sha"  = var.commit_sha
  }

  subnetwork = var.vm_subnet
  tags       = local.vm_tags

  skip_create_image = var.skip_create_image
}
