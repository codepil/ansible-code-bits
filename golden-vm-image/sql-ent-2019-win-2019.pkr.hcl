source "googlecompute" "sql-ent-2019-win-2019" {
  disk_size    = 50 // necessary for how big these images are
  communicator = "winrm"

  account_file   = var.gcp_creds
  project_id     = var.project_id
  winrm_username = "packer"
  winrm_insecure = true
  winrm_use_ssl  = true
  metadata = {
    windows-startup-script-cmd = "winrm quickconfig -quiet & net user /add packer_user & net localgroup administrators packer_user /add & winrm set winrm/config/service/auth @{Basic=\"true\"}"
  }
  source_image_family = "sql-ent-2019-win-2019"
  zone                = var.zone

  image_name        = "sql-ent-2019-win-2019-v${formatdate("YYYYMMDDhhmm", timestamp())}-golden"
  image_description = "Golden SQL Enterprise 2019 Windows Server 2019: Base Image"
  image_family      = "sql-ent-2019-win-2019"
  image_labels = {
    "os"          = "gold-sql-ent-2019-win-2019"
    "created_by"  = "packer"
    "environment" = var.environment
    "commit_sha"  = var.commit_sha
  }

  subnetwork = var.vm_subnet
  tags       = local.vm_tags

  skip_create_image = var.skip_create_image
}
