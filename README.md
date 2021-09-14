# security-lab

Complete ansible project to deploy 

## Prerequisites

- DNS Servers are configured
- Host with ansible is pointing to the correct DNS servers

## Configuration

### Recommendation 

This whole thing can get quite tedious, so take make your life easier user the below steps

1. Spin up windows hosts everything you think you'll want (Servers and Workstations)
2. Configure earch one with the necessary software and drivers (Firefox, Notepad++, Qemu Guest Agent, Etc.) 
3. Copy the `scripts/windows/configure_windows_winrm.ps1` script over to the host and run it
4. Copy the `scripts/windows/configure_windows_ip.ps1` script over
5. Create a template from the configured hosts
6. When you spin up new hosts from the template, run the `configure_windows_ip.ps1` script to configure IP and Hostname

### Windows

Windows WinRM needs to be configured on the windows hosts to work work with ansible

There are powershell scripts in `scripts/windows`

- `configure_windows_winrm.ps1` is used to configure the WinRM listeners and create the ansible users
- `configure_windows_ip.ps1` is used to configure the static IP address and Hostname

### To Do
- [ ] Domain Join Role
- [ ] Linux Universal Forwarder Role
- [ ] Splunk Enterprise Server Role
