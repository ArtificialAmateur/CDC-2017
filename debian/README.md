# Debian Hardening Script

#### Users

- Lock root account
- `pam.d` configuration
    - Complexity requirements
    - Lockout policy
- `auditd` policy
- Password policy
- sudoers configuration
- rsyslog policy

#### Networking
- Clear hosts file
- Fix `sshd` configuration
- Configure firewall (ufw)
    - Reset then enable firewall
    - Set default behavior to deny
    - Allow and limit SSH
    - Turn logging on
- Turn on SYN Cookie Protection
- Disable IPv6
- Configure sysctl redirects
- Disable uncommon protocols

#### Software
- Clear `apt` sources list
- Disable redundant filesystems
- Disable core dumps
- Secure RAM
- Update/upgrade the system/distro
- Check for updates daily
- Secure GRUB
- Scan with lynis, chrootkit, rkhunter, clamav
- Setup AIDE

#### TODO
- Intense testing
- Auto-backup
