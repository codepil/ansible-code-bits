
build {
  name = "linux-builder"
  sources = [
    "googlecompute.rhel-7",
    "googlecompute.rhel-8",
    "googlecompute.ubuntu-1804-lts",
    "googlecompute.ubuntu-2004-lts",
  ]

  # Ansible Provisioner that applies Redhat 7 and 8 OSCB Settings
  provisioner "ansible" {
    only = [
        "googlecompute.rhel-7",
        "googlecompute.rhel-8",
    ]
    user          = "packer"
    sftp_command =  "/usr/libexec/openssh/sftp-server"
    playbook_file = "${path.root}/ansible/redhat_hardening.yml"
  }

  # Ansible Provisioner that applies Ubuntu 18.04 and 20.04 OSCB Settings
  provisioner "ansible" {
    only = [
    "googlecompute.ubuntu-1804-lts",
    "googlecompute.ubuntu-2004-lts",
    ]
    user          = "packer"
    playbook_file = "${path.root}/ansible/ubuntu_hardening.yml"
  }
}
