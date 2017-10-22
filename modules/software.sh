#!/bin/bash

echo $'\n[>] Software'


#-|-------------- apt Sources --------------|-

cp /etc/apt/sources.list data/backup_files/sources.list.backup
cat data/references/sources.list > /etc/apt/sources.list
echo "  [+] Cleaned apt sources."


#-|-------------- Config Security --------------|-

cp /etc/resolv.conf data/backup_files/resolv.conf
cat data/references/resolv.conf > /etc/resolv.conf

cp /etc/rc.local data/backup_files/rc.local.backup
cat data/references/rc.local > /etc/rc.local
echo "  [+] Secured certain configuration files."


#-|-------------- Disable Redundant Filesystems --------------|-

echo "  [+] Disabling redundant filesystems..."
touch /etc/modprobe.d/CIS.conf
cat >/etc/modprobe.d/CIS.conf <<-EOF
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF


#-|-------------- Disable Core Dumps --------------|-

echo "  [+] Disabling core dumps..."
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

#-|-------------- Secure RAM --------------|-

echo "  [+] Securing RAM..."
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf


#-|-------------- Updates --------------|-

# Update system
read -p "  [?] Update/upgrade the system/distro? (y/n) " choice
case "$choice" in
  y|Y ) apt -y -qq update && apt -y -qq upgrade && apt -y -qq dist-upgrade && apt -y -qq autoremove && apt -y -qq autoclean && echo "  [+] System upgraded.";;
esac


# Check for updates daily
if ! grep -q "APT::Periodic::Update-Package-Lists \"1\";" /etc/apt/apt.conf.d/10periodic; then
    sed -i 's/APT::Periodic::Update-Package-Lists "0";/APT::Periodic::Update-Package-Lists "1";/g' /etc/apt/apt.conf.d/10periodic
    echo "  [+] Daily updates configured."
fi

#-|-------------- Secure GRUB --------------|-

echo "  [+] Hardening GRUB..."
cp /boot/grub2/grub.cfg /boot/grub2/grub.cfg.backup
cp /etc/grub.d/10_linux /etc/grub.d/10_linux.backup
echo "cat <<EOF
set superusers=”bobby”
Password bobby f1%FvmieeAj-cDmFLn5RvjYphj3iL1RJ&Z
EOF" >> /etc/grub.d/10_linux
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg

#-|-------------- Fix NTP --------------|-

if ! dpkg -s ntp >/dev/null 2>&1; then
    echo "  [+] Installing ntp..." &&
    apt -qq -y install ntp
fi

echo "  [+] Setting up NTP..."
cat > /etc/ntp.conf <<-EOF
driftfile /var/lib/ntp/drift
restrict default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery
restrict 127.0.0.1
restrict ::1
server time.nist.gov iburst
server utcnist.colorado.edu iburst
server utcnist2.colorado.edu iburst
server nist-time-server.eoni.com iburst
includefile /etc/ntp/crypto/pw
keys /etc/ntp/keys
disable monitor
EOF
echo "OPTIONS=\"-u ntp:ntp\"" >> /etc/sysconfig/ntpd
systemctl start ntpd
systemctl enable ntpd

#-|------------------ Cron -----------------|-

echo "  [+] Enabling cron..."
systemctl enable crond
echo "  [+] Restricting crontab permissions..."
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d
echo "  [+] Restricting daemon permissions..."
rm -f /etc/at.deny
rm -f /etc/cron.deny
touch /etc/at.allow
touch /etc/cron.allow
chown root:root /etc/at.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chmod og-rwx /etc/cron.allow


#-|------------------ Scans -----------------|-

# Second scanner
read -p "  [?] Scan with chkrootkit? (y/n) " choice
case "$choice" in
y|Y ) if ! dpkg -s chkrootkit >/dev/null 2>&1; then echo "    [+] Installing chkrootkit..." &&
apt -qq -y install chkrootkit; fi && echo $'\n    [+] Scanning with chkrootkit...' &&
chkrootkit
esac

# Third scanner
read -p "  [?] Scan with rkhunter? (y/n) " choice
case "$choice" in
y|Y ) if ! dpkg -s rkhunter >/dev/null 2>&1; then echo "    [+] Installing rkhunter..." &&
apt -qq -y install rkhunter; fi
esac

# Fourth scanner
read -p "  [?] Scan with clamav? (y/n) " choice
case "$choice" in
y|Y ) if ! dpkg -s clamav >/dev/null 2>&1; then echo "    [+] Installing clamav..." &&
apt -qq -y install clamav clamav-daemon; fi && echo $'\n    [+] Scanning with clamav...' &&
freshclam &>/dev/null && 
clamscan -i -r /
esac

# Fifth scanner
read -p "  [?] Setup AIDE? (y/n) " choice
case "$choice" in
y|Y ) if ! dpkg -s aide >/dev/null 2>&1; then echo "    [+] Installing AIDE..." &&
apt -qq -y install aide; fi && echo "  [+] Enabling AIDE..." &&
aide --init -B 'database_out=file:/var/lib/aide/aide.db.gz'
mv data/chkaide.sh /usr/sbin/
# Schedule daily file integrity checks
echo "*/15 * * * * root /usr/sbin/chkaide.sh" >> /etc/crontab
esac
