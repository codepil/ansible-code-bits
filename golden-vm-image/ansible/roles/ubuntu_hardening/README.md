Ubuntu 20.04 Hardening 
======================

Most of the hardening is from CIS_Ubuntu_Linux_20.04/18.04_LTS_Benchmark_v1.1.0 dated 03-31-2021 https://www.cisecurity.org/.

This role **will make changes to the system** that could break things. This is not an auditing tool but rather a remediation tool to be used after an audit has been conducted.

This role was developed against a clean install of the Ubuntu 20.04 or 18.04 Operating System. 
If you are implementing to an existing system please review this role for any site specific changes that are needed.


```
### - name: "1.1.5| Ensure noexec option set on /tmp partition"
It is not implemented, noexec for /tmp will disrupt apt. /tmp contains executable scripts during package installation
```
