
packer {
  required_plugins {
    windows-update = {
      version = "0.14.0"
      source  = "github.com/rgl/windows-update"
    }
  }
}

build {
  name = "windows-builder"
  sources = [
    "googlecompute.windows-2016",
    "googlecompute.windows-2016-core",
    "googlecompute.windows-2019",
    "googlecompute.windows-2019-core",
    "googlecompute.sql-ent-2019-win-2019",
    "googlecompute.sql-std-2019-win-2019",
    "googlecompute.sql-ent-2016-win-2016",
    "googlecompute.sql-std-2016-win-2016"
  ]
  # Script that improves Ansible/Powershell command execution time
  provisioner "powershell" {
    script = "${path.root}/ansible/files/windows/windows_performance.ps1"
  }

  # Ansible Provisioner that applies Windows 2019 OSCB Settings
  provisioner "ansible" {
    only = [
      "googlecompute.windows-2019",
      "googlecompute.windows-2019-core",
      "googlecompute.sql-ent-2019-win-2019",
      "googlecompute.sql-std-2019-win-2019"
    ]
    user          = "packer"
    use_proxy     = false
    playbook_file = "${path.root}/ansible/windows_2019_hardening.yml"
    ansible_env_vars = [
      "no_proxy=\"*\"",
      "ANSIBLE_NOCOLOR=1",
      "ANSIBLE_GATHER_TIMEOUT=30"
    ]
    extra_arguments = [
      "--extra-vars",
      "ansible_winrm_server_cert_validation=ignore",
      # "-vvv"
    ]
  }

  # Reboot before Patching
  provisioner "windows-restart" {}

  # Apply all updates that are not currently installed.
  provisioner "windows-update" {
    search_criteria = "IsInstalled=0"
    filters = [
      "include:$true"
    ]
  }
  # Reboot after patching and before Sysprep
  provisioner "windows-restart" {}

  # Run Google sysprep command before image is created.
  provisioner "powershell" {
    inline = ["GCESysprep -no_shutdown"]
  }
}
