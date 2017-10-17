#!/bin/bash

##########################
## Disable Root Account ##
##########################
echo "  [+] Disabling root account..."
sed -i "s|root:x:0:0:root:/root:/bin/bash|root:x:0:0:root:/root:/sbin/nologin|g" /etc/passwd
echo > /etc/securetty

###################################
## Disable Redundant Filesystems ##
###################################
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


#######################
## Enforce GPG Check ##
#######################
echo "  [+] Enforcing GPG check..."
if grep 'gpgcheck=0'; then
    sed -i 's/gpgcheck=0/gpgcheck=1/g' /etc/yum.conf
fi


###########################
## Add Third-Party Repos ##
###########################
echo "  [+] Adding third-party repos..."
yum install epel-release -y
rpm --import https://www.elrepo.org/RPM-GPG-KEY-elrepo.org
rpm -Uvh http://www.elrepo.org/elrepo-release-7.0-3.el7.elrepo.noarch.rpm
yum clean all


#######################
## Update the Server ##
#######################
echo "  [+] Upgrading the system..."
yum update -y && yum upgrade -y


#########################
## Enable Auto Updates ##
#########################
echo "  [+] Enabling auto-updates..."
yum install yum-cron -y
sed -i 's/apply_updates = no/apply_updates = yes/g' /etc/yum/yum-cron.conf
systemctl start yum-cron
systemctl enable yum-cron


####################################
## Remove MCS Translation Service ##
####################################
yum erase mcstrans -y


################################
## Set Root Ownership on GRUB ##
################################
echo "  [+] Hardening GRUB..."
cp /boot/grub2/grub.cfg /boot/grub2/grub.cfg.backup
cp /etc/grub.d/10_linux /etc/grub.d/10_linux.backup
echo "cat <<EOF
set superusers=”bobby”
Password bobby f1%FvmieeAj-cDmFLn5RvjYphj3iL1RJ&Z
EOF" >> /etc/grub.d/10_linux
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg


########################
## Disable Core Dumps ##
########################
echo "  [+] Disabling core dumps..."
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf


#######################################################
## Enable Randomised Virtual Memory Region Placement ##
#######################################################
echo "  [+] Securing RAM..."
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf


####################################
## Remove/Disable Legacy Services ##
####################################
echo "  [+] Disabling legacy services..."
chkconfig chargen-dgram off
chkconfig chargen-stream off
chkconfig daytime-dgram off
chkconfig daytime-stream off
chkconfig echo-dgram off
chkconfig echo-stream off
chkconfig tcpmux-server off


######################
## Set Daemon Umask ##
######################
echo "umask 027" >> /etc/sysconfig/init


############################
## Remove X Window System ##
############################
cd /etc/lib/systemd/system/
unlink default.target
ln -s /usr/lib/systemd/system/multi-user.target default.target
yum remove xorg-x11-server-common -y


#############################
## Remove/Disable Services ##
#############################
systemctl disable avahi-daemon cups nfslock rpcgssd rpcbind rpcidmapd rpcsvcgssd

yum erase dhcp openldap-servers openldap-clients bind vsftpd httpd dovecot samba squid net-snmp telnet-server telnet rsh-server rsh ypbind ypserv tftp tftp-server talk talk-server xinetd -y


#############
## Fix NTP ##
#############
yum install ntp -y
cat > /etc/ntp.conf <<-EOF
driftfile /var/lib/ntp/drift
restrict default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery
restrict 127.0.0.1
restrict ::1
server 0.centos.pool.ntp.org iburst
server 1.centos.pool.ntp.org iburst
server 2.centos.pool.ntp.org iburst
server 3.centos.pool.ntp.org iburst
includefile /etc/ntp/crypto/pw
keys /etc/ntp/keys
disable monitor
EOF

echo "OPTIONS=\"-u ntp:ntp\"" >> /etc/sysconfig/ntpd

systemctl start ntpd
systemctl enable ntpd


####################################
## Set Postfix to Local-Only Mode ##
####################################
sed -i 's/^inet_interfaces .*$/inet_interfaces = localhost/g' /etc/postfix/main.cf
systemctl restart postfix


###########################
## Network Configuration ##
###########################
echo "net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0" >> /etc/sysctl.conf

/sbin/sysctl -w net.ipv4.ip_forward=0
/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0
/sbin/sysctl -w net.ipv4.conf.default.send_redirects=0
/sbin/sysctl -w net.ipv4.conf.all.accept_source_route=0
/sbin/sysctl -w net.ipv4.conf.default.accept_source_route=0
/sbin/sysctl -w net.ipv4.conf.all.accept_redirects=0
/sbin/sysctl -w net.ipv4.conf.default.accept_redirects=0
/sbin/sysctl -w net.ipv4.conf.all.secure_redirects=0
/sbin/sysctl -w net.ipv4.conf.default.secure_redirects=0
/sbin/sysctl -w net.ipv4.conf.all.log_martians=1
/sbin/sysctl -w net.ipv4.conf.default.log_martians=1
/sbin/sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
/sbin/sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
/sbin/sysctl -w net.ipv4.conf.all.rp_filter=1
/sbin/sysctl -w net.ipv4.conf.default.rp_filter=1
/sbin/sysctl -w net.ipv4.tcp_syncookies=1
/sbin/sysctl -w net.ipv4.route.flush=1
/sbin/sysctl -w net.ipv6.conf.all.accept_ra=0
/sbin/sysctl -w net.ipv6.conf.default.accept_ra=0
/sbin/sysctl -w net.ipv6.conf.all.accept_redirects=0
/sbin/sysctl -w net.ipv6.conf.default.accept_redirects=0
/sbin/sysctl -w net.ipv6.route.flush=1

yum install tcp_wrappers -y


#############################
## Create /etc/hosts.allow ##
#############################
echo "ALL: 10.1.1.0/255.255.255.0" >> /etc/hosts.allow
chmod 644 /etc/hosts.allow


############################
## Create /etc/hosts.deny ##
############################
echo "ALL: ALL" >> /etc/hosts.deny
chmod 644 /etc/hosts.deny


########################################
## Disable Uncommon Network Protocols ##
########################################
echo "install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true" >> /etc/modprobe.d/CIS.conf


######################
## Enable Firewalld ##
######################
yum install firewalld -y
systemctl enable firewalld
systemctl start firewalld


####################
## Install Syslog ##
####################
yum install rsyslog -y
systemctl enable rsyslog
systemctl start rsyslog


######################
## Configure Syslog ##
######################
cat >/etc/rsyslog.conf <<-EOF
\$ModLoad imuxsock
\$ModLoad imjournal
\$WorkDirectory /var/lib/rsyslog
\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
\$IncludeConfig /etc/rsyslog.d/*.conf
\$OmitLocalLogging on
\$IMJournalStateFile imjournal.state
*.info;authpriv.none;cron.none /var/log/messages
auth,user.* /var/log/messages
kern.* /var/log/kern.log
daemon.* /var/log/daemon.log
syslog.* /var/log/syslog
lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log
authpriv.* /var/log/secure
mail.* /var/log/maillog
cron.* /var/log/cron
*.emerg :omusrmsg:*
uucp,news.crit /var/log/spooler
local7.* /var/log/boot.log
*.* @@10.1.1.122:514
EOF

touch /var/log/kern.log
chown root:root /var/log/kern.log
chmod og-rwx /var/log/kern.log

systemctl restart rsyslog


########################
## Configure Auditing ##
########################
systemctl start auditd
systemctl enable auditd

cat > /etc/audit/auditd.conf <<-EOF
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root
priority_boost = 4
flush = INCREMENTAL
freq = 20
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
##name = mydomain
max_log_file = 100
max_log_file_action = keep_logs
space_left = 75
space_left_action = email
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = halt
disk_full_action = SUSPEND
disk_error_action = SUSPEND
##tcp_listen_port =
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
EOF


##############################################################
## Enable Auditing for Processes that Start Prior to auditd ##
##############################################################
echo 'GRUB_CMDLINE_LINUX="audit=1"' >> /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg


#########################################################
## Record Events that Modify Date and Time Information ##
#########################################################
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change 
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change 
-a always,exit -F arch=b32 -S clock_settime -k time-change 
-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/audit.rules


######################################################
## Record Events that Modify User/Group Information ##
######################################################
echo "-w /etc/group -p wa -k identity 
-w /etc/passwd -p wa -k identity 
-w /etc/gshadow -p wa -k identity 
-w /etc/shadow -p wa -k identity 
-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/audit.rules


############################################################
## Record Events that Modify System's Network Environment ##
############################################################
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale 
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale 
-w /etc/issue -p wa -k system-locale 
-w /etc/issue.net -p wa -k system-locale 
-w /etc/hosts -p wa -k system-locale 
-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules


#########################################################
## Record Events that Modify Mandatory Access Controls ##
#########################################################
echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules


#####################################
## Collect Login and Logout Events ##
#####################################
echo "-w /var/log/faillog -p wa -k logins 
-w /var/log/lastlog -p wa -k logins 
-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/audit.rules


############################################
## Collect Session Initiation Information ##
############################################
echo "-w /var/run/utmp -p wa -k session 
-w /var/log/wtmp -p wa -k session 
-w /var/log/btmp -p wa -k session" >> /etc/audit/rules.d/audit.rules


#########################################################################
## Collect Discretionary Access Control Permission Modification Events ##
#########################################################################
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules


###############################################################
## Collect Unsuccessful Unauthorised Access Attemps to Files ##
###############################################################
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules


########################################
## Collect Use of Privileged Commands ##
########################################


###########################################
## Collect Successful File System Mounts ##
###########################################
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts 
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules


##########################################
## Collect File Deletion Events by User ##
##########################################
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete 
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules


####################################################
## Collect Changes to System Administration Scope ##
####################################################
echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/audit.rules


##########################################
## Collect System Administrator Actions ##
##########################################
echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules


#################################################
## Collect Kernel Module Loading and Unloading ##
#################################################
echo "-w /sbin/insmod -p x -k modules 
-w /sbin/rmmod -p x -k modules 
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules


############################################
## Make the Audit Configuration Immutable ##
############################################
echo "-e 2" >> /etc/audit/rules.d/audit.rules

pkill -HUP -P 1 auditd


#########################
## Configure Logrotate ##
#########################
yum install logrotate -y


####################
## Enable Anacron ##
####################
yum install cronie-anacron -y


##################
## Enable Crond ##
##################
systemctl enable crond


###########################################
## Set User/Group Permissions on Anacron ##
###########################################
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab


########################################
## Set User/Group Permissions on Cron ##
########################################
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


########################
## Restrict At Daemon ##
########################
rm -f /etc/at.deny
rm -f /etc/cron.deny
touch /etc/at.allow
touch /etc/cron.allow
chown root:root /etc/at.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chmod og-rwx /etc/cron.allow


#######################
## SSH Configuration ##
#######################
sed -i 's/^Protocol .*$/Protocol 2/g' /etc/ssh/sshd_config
sed -i 's/^LogLevel .*$/LogLevel INFO/g' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
sed -i 's/^MaxAuthTries .*$/MaxAuthTries 4/g' /etc/ssh/sshd_config
sed -i 's/IgnoreRhosts no/IgnoreRhosts yes/g' /etc/ssh/sshd_config
sed -i 's/HostbasedAuthentication yes/HostbasedAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/PermitEmptyPasswords yes/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/PermitUserEnvironment yes/PermitUserEnvironment no/g' /etc/ssh/sshd_config
sed -i 's/^Ciphers .*$/Ciphers aes128-ctr,aes192-ctr,aes256-ctr/g' /etc/ssh/sshd_config
sed -i 's/^ClientAliveInterval .*$/ClientAliveInterval 300/g' /etc/ssh/sshd_config
sed -i 's/^ClientAliveCountMax .*$/ClientAliveCountMax 0/g' /etc/ssh/sshd_config

chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config


###################
## Configure PAM ##
###################
echo "  [+] Configuring password policy..."
authconfig --passalgo=sha512 --update
users="$(cat /etc/passwd | grep 'bash\|zsh\|ksh\|fish\|tcsh\|csh' | awk -F: '{ print $1 }')"
for i in $users; do
    chage -E 01/01/2019 -m 5 -M 90 -I 30 -W 14 $i
done
echo "auth     required       pam_tally2.so file=/var/log/tallylog deny=3 even_deny_root unlock_time=60" >> /etc/pam.d/password-auth
echo "password    required    pam_pwquality.so retry=3" >> /etc/pam.d/passwd
echo "minlen = 8 
minclass = 4
maxsequence = 3 
maxrepeat = 3" >> /etc/security/pwquality.conf



#############################################################
## Install Advanced Intrusion Detection Environment (AIDE) ##
#############################################################
echo "  [+] Enabling AIDE..."
yum install aide -y
aide --init -B 'database_out=file:/var/lib/aide/aide.db.gz'
mv data/chkaide.sh /usr/sbin/

# Schedule daily file integrity checks
echo "0 5 * * * root /usr/sbin/chkaide.sh" >> /etc/crontab









###############
## MOSCOVIUM ##
###############


echo $'\n[>] Users'


#-|-------------- Purge accounts  --------------|-

cp_input_accounts(){
    # Clear valid_admins and valid_users
    echo '' > valid_admins
    echo '' > valid_users

    read -p '      [+] Please enter the valid admins: ' -a admins
    printf '%s\n' "${admins[@]}" >> data/valid_admins
    read -p '      [+] Please enter the valid standard users: ' -a users
    printf '%s\n' "${users[@]}" >> data/valid_users
} 

cp_purge_accounts(){
    # All valid admins are also valid users
    if ! grep -wq -f data/valid_admins data/valid_users; then
    	cat data/valid_admins >> data/valid_users
    fi

    # Get system users and admins
    admins="$(grep -Po '^sudo.+:\K.*$' /etc/group | tr "," "\n")"
    users="$(cat /etc/passwd | grep bash | awk -F: '{ print $1 }')"

    # Purge users
    for i in $users; do
        if grep -Fxqs "$i" 'data/valid_users'; then
            # If user is authorized
            chage -E 01/01/2019 -m 5 -M 90 -I 30 -W 14 $i
            if [ "$i" != "$cp_my_user" ]; then
                echo "$i:"'CA935_CyberPatriots!' | chpasswd
                echo "        [+] $i password changed and chage password policy set."
            fi
            if [ "$i" = "$cp_my_user" ]; then
                echo "      [+] $i chage password policy set."
            fi
        else
            if [ "$i" != "root" ]; then
                read -p "      [?] $i is not an authorized user. Remove them and their files? (y/n) " choice
                case "$choice" in 
                  y|Y ) userdel -r $i &>/dev/null && echo "      [+] $i removed.";;
                esac
            fi
        fi
    done

    # Purge admins
    for i in $admins; do
        if ! grep -Fxqs "$i" 'data/valid_admins'; then
            gpasswd -d $i sudo &>/dev/null
            echo "    [+] $i is not an authorized admin. $i removed from sudo group."    
        fi
    done
}

read -p "  [?] Edit and correct valid admins and users? (y/n) " choice
case "$choice" in 
  y|Y ) read -p "    [?] What is your username? " cp_my_user && cp_input_accounts && cp_create_accounts && cp_purge_accounts;;
esac

#-|-------------- Lock root account --------------|-

if ! passwd -S | grep -q "root L"; then
    echo "root:"'$1$FvmieeAj$cDmFLn5RvjYphj3iL1RJZ/' | chpasswd -e
    passwd -l root 2>&1>/dev/null
    echo "  [+] Root account locked."
fi


#-|-------------- lightdm Config --------------|-

cp /etc/lightdm/lightdm.conf data/backup_files/lightdm.conf
cp -f data/references/lightdm.conf /etc/lightdm/lightdm.conf
echo "  [+] Lightdm file secured."


#-|-------------- sudoers Config --------------|-

cp /etc/sudoers data/backup_files/sudoers.backup
cp -f data/references/sudoers /etc/sudoers
echo "  [+] Sudoers file secured."


#-|-------------- Password Policy --------------|-

if ! dpkg -s libpam-cracklib >/dev/null 2>&1; then
    echo "  [+] Installing libpam-cracklib..." &&
    apt-get -qq -y install libpam-cracklib
fi

cp /etc/login.defs data/backup_files/login.defs.backup
cp -f data/references/login.defs /etc/login.defs

cp /etc/pam.d/common-password data/backup_files/common-password.backup
cp -f data/references/common-password /etc/pam.d/common-password

cp /etc/pam.d/common-auth data/backup_files/common-auth.backup
cp -f data/references/common-auth /etc/pam.d/common-auth

echo "  [+] Password policy set."

#-|-------------- audtid Policy --------------|-

if ! dpkg -s auditd >/dev/null 2>&1; then
    echo "  [+] Installing auditd..." &&
    apt-get -qq -y install auditd
    auditctl -e 1 &>/dev/null
    echo "    [+] Audit policy set with auditd."
fi

echo $'\n[>] Networking'


#-|-------------- Hosts File --------------|-

echo '127.0.0.1' $HOSTNAME >> data/references/hosts
cp /etc/hosts data/backup_files/hosts.backup
cp -f data/references/hosts /etc/hosts
echo "  [+] Cleaned hosts file."


#-|-------------- SSHD Config --------------|-

cp /etc/ssh/ssh_config data/backup_files/ssh_config.backup
cp -f data/references/ssh_config /etc/ssh/ssh_config

cp /etc/ssh/sshd_config data/backup_files/sshd_config.backup
cp -f data/references/sshd_config /etc/ssh/sshd_config
echo "  [+] Secured ssh settings."


#-|-------------- Firewall --------------|-

if ! dpkg -s ufw >/dev/null 2>&1; then 
    echo "    [+] Installing ufw..."
    apt-get -qq -y install ufw
fi
echo "y" | ufw reset >/dev/null
ufw default deny >/dev/null 2>&1
ufw logging on >/dev/null 2>&1

services_length="$(sed -n '$=' data/valid_admins)"
for ((i=1; i<=services_length; i++)); do
	service="$(awk 'FNR == $i { print; exit }' data/critical_services | tr '[:lower:]' '[:upper:]')"
	ufw allow $service >/dev/null 2>&1
	if [ "$service" = "SSH" ]; then
		ufw limit SSH >/dev/null 2>&1
	fi
done
ufw enable >/dev/null 2>&1
echo "  [+] Firewall configured."


#-|-------------- Ports? --------------|-

cp_ports(){
    echo $'\n[>] Open Ports'

    # Shows all listening ports, as well as the services running on them. If
    # the service isn't required, you should remove it.

    rm ./open_ports 2>&1>/dev/null
    echo "   [+] Open ports:"
    netstat -tulpnwa | grep 'LISTEN\|ESTABLISHED' | grep -v "tcp6\|udp6" | awk '{ print $4 " - " $7 }' | awk -F: '{ print "	IPV4 - " $2 }' >> ./open_ports
    netstat -tulpnwa | grep 'LISTEN\|ESTABLISHED' | grep "tcp6\|udp6" | awk '{ print $4 " - " $7 }' | awk -F: '{ print "	IPV6 - " $4 }' >> ./open_ports

    while read l; do
        echo $l
        pid=$(echo $l | awk '{ print $5 }' | awk -F/ '{ print $1 }')
        #printf "\tRunning from: $(ls -la /proc/$pid/exe | awk '{ print $11 }')\n"
        command="$(cat /proc/$pid/cmdline | sed 's/\x0/ /g' | sed 's/.$//')"
        #echo "$command"
        if [[ "$command" == *"nc -l"* ]]; then
            for i in $(grep -s -r --exclude-dir={proc,lib,tmp,usr,var,libproc,sys,run,dev} "$command" $(ls -l /proc/$pid/cwd | awk '{ print $11 }') | awk -F: '{ print $1 }'); do
                printf "   [!]  $i\n"
            done
        fi
    done < ./open_ports | sed 's/^/        /' 

    # Monitor network

    echo $'\n[>] Listening Network Connections'
    netstat -ntulp | sed 's/^/        /' 
}


#-|-------------- apache2 Config --------------|-

if [ -e /etc/apache2/apache2.conf ]; then
	echo '<Directory>' >> /etc/apache2/apache2.conf
	echo -e ' \t AllowOverride None' >> /etc/apache2/apache2.conf
	echo -e ' \t Order Deny,Allow' >> /etc/apache2/apache2.conf
	echo -e ' \t Deny from all' >> /etc/apache2/apache2.conf
	echo '<Directory/>' >> /etc/apache2/apache2.conf
	echo UserDir disabled root >> /etc/apache2/apache2.conf
	echo "  [+] apache2 configured."
fi


#-|-------------- Miscellaneous Network Settings --------------|-

# SYN Cookie Protection
if grep -q 0 /proc/sys/net/ipv4/tcp_syncookies; then 
	echo 1 > /proc/sys/net/ipv4/tcp_syncookies
	echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
	echo "  [+] SYN cookie protection enabled."
fi

# Disable IPv6
if grep -q 0 /proc/sys/net/ipv6/conf/all/disable_ipv6; then
	echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
	echo 'net.ipv6.conf.all.disable_ipv6 = 1' >> /etc/sysctl.conf
	echo "  [+] IPv6 Disabled."
fi 

# Don't act as router
(sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0 )  &>/dev/null

# Make sure no one can alter the routing tables
(sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0)  &>/dev/null



echo $'\n[>] Software'


#-|-------------- Cron --------------|-

read -p "  [?] Check for running cron jobs? (y/n) " choice
case "$choice" in 
  y|Y ) for user in $(cut -f1 -d: /etc/passwd); do crontab -u $user -l; done
esac


#-|-------------- apt Sources --------------|-

cp /etc/apt/sources.list data/backup_files/sources.list.backup
cp -f data/references/sources.list /etc/apt/sources.list
echo "  [+] Cleaned apt sources."


#-|-------------- Config Security --------------|-

cp /etc/resolv.conf data/backup_files/resolv.conf
cp -f data/references/resolv.conf /etc/resolv.conf

cp /etc/rc.local data/backup_files/rc.local.backup
cp -f data/references/rc.local /etc/rc.local
echo "  [+] Secured certain configuration files."


#-|-------------- Unauthorized Files --------------|-

echo "" > 'data/unauthorized_media'
(find /home -name "*.mp3"
find /home -name "*.wav"
find /home -name "*.wma"
find /home -name "*.aac"
find /home -name "*.mp4"
find /home -name "*.mov"
find /home -name "*.avi"
find /home -name "*.gif"
find /home -name "*.jpg"
find /home -name "*.jpeg"
find /home -name "*.png"
find /home -name "*.bmp"
find /home -name "*.exe"
find /home -name "*.msi"
find /home -name "*.bat"
find /home -name "*.sh") >> 'data/unauthorized_media'

# Remove authorized media files from list
for i in $(echo "CP-IX "; echo "ubuntu-14"; echo ".cache"; echo "Trash"); do
    sed -i "/$i/d" 'data/unauthorized_media'
done

# Delete unauthorized media
unauth_media="$(cat data/unauthorized_media)"
if [ -n "$unauth_media" ]; then
	echo "  [>] Unauthorized files"
	cat 'data/unauthorized_media' | sed 's/^/  /'
	read -p $'\n  [?] Delete all unauthorized media? (y/n) ' choice
	case "$choice" in
	y|Y ) sed -i '/[>]/d' 'data/unauthorized_media' &&
		sed -i '/^$/d' 'data/unauthorized_media' &&
		xargs -0 rm -r < <(tr \\n \\0 <'data/unauthorized_media')&>/dev/null || true &&
		echo "    [+] Unauthorized media deleted.";;
	esac
fi


#-|-------------- Unwanted Programs --------------|-

unwanted_programs="$(dpkg --get-selections | grep -E '^(apache|cupsd|master|nginx|nmap|medusa|john|nikto|hydra|tightvnc|bind|vsftpd|netcat)' | grep -v 'bind9-host' | grep -v 'deinstall')"
if [ -n "$unwanted_programs" ]; then
    echo "  [+] Potentially unwanted programs:"
    echo "$unwanted_programs" | grep -o '^\S*' > data/uninstalled_packages
    cat data/uninstalled_packages | sed 's/^/    /'
    read -p "  [?] Remove all these programs? (y/n) " choice
    case "$choice" in
    y|Y ) apt-get purge --auto-remove $(<'data/uninstalled_packages') && echo "  [+] Unwanted programs removed.";;
    esac
fi

#-|-------------- Unwanted Services --------------|-

cp_purge_services(){
  echo "    [+] Potentially unwanted services:"
	echo "$services_to_delete" | sed 's/^/      /'
	read -p "    [?] Disable these services? (y/n) " choice
	case "$choice" in
	y|Y ) while read -r s; do
        service $s stop
        update-rc.d $s disable
      done <<< "$services_to_delete"
	 ;;
	esac
}

cp_verify_services(){
  # Spacing is important here
  while read -r s; do
    if pgrep $s >/dev/null 2>&1; then
      if [ -n "$services_to_delete" ]; then
        services_to_delete="${services_to_delete}
${s}"
      else
        services_to_delete="${services_to_delete}${s}"
      fi
    fi
  done <<< "$unwanted_services"

  # Make the newline count
  unwanted_services="$(echo -e "$services_to_delete")"
}

unwanted_services="$(service --status-all |& grep -wEo '(mysqld|postgres|dovecot|exim4|postfix|nfs|nmbd|rpc.mountd|rpc.nfsd|smbd|vsftpd|mpd|bind|dnsmasq|xinetd|inetd|telnet|cupsd|saned|ntpd|cron|apache2|httpd|jetty|nginx|tomcat)' | grep -v $(<data/critical_services) | grep -v "[ - ]")"
services_to_delete="$(echo '')"

# Because -service --status-all is trash, verify if services are running
cp_verify_services

if [ -n "$unwanted_services" ]; then
  read -p $'  [?] Purge unwanted services? (y/n) ' choice
  case "$choice" in
    y|Y ) read -p $'    [?] Edit critical services? (y/n) ' choice
          case "$choice" in
          y|Y ) nano data/critical_services && cp_purge_services;;
          * ) cp_purge_services;;
          esac;
  esac
fi



#-|-------------- Updates --------------|-

# Update system
read -p "  [?] Update/upgrade the system/distro? (y/n) " choice
case "$choice" in
  y|Y ) apt-get -y update && apt-get -y upgrade && apt-get dist-upgrade && apt-get -y install firefox && echo "  [+] System upgraded.";;
esac


# Check for updates daily
if ! grep -q "APT::Periodic::Update-Package-Lists \"1\";" /etc/apt/apt.conf.d/10periodic; then
    sed -i 's/APT::Periodic::Update-Package-Lists "0";/APT::Periodic::Update-Package-Lists "1";/g' /etc/apt/apt.conf.d/10periodic
    echo "  [+] Daily updates configured."
fi


#-|-------------- Media Codecs --------------|-

if ! dpkg -s gstreamer1.0-plugins-good >/dev/null 2>&1; then
  read -p $'\n  [?] Install media codecs? (y/n) ' choice
  case "$choice" in
  y|Y )  echo "  [+] Installing media codecs..." &&
         apt-get -qq -y install gstreamer1.0-plugins-good ubuntu-restricted-extras
  esac
fi


#-|------------------ Scans -----------------|-

# First scanner
read -p "  [?] Scan with lynis? (y/n) " choice
case "$choice" in
y|Y ) if ! dpkg -s lynis >/dev/null 2>&1; then echo "    [+] Installing lynis..." &&
apt-get -qq -y install lynis; fi && echo $'\n    [+] Scanning with lynis...' &&
lynis -Q
esac

# Second scanner
read -p "  [?] Scan with chkrootkit? (y/n) " choice
case "$choice" in
y|Y ) if ! dpkg -s chkrootkit >/dev/null 2>&1; then echo "    [+] Installing chkrootkit..." &&
apt-get -qq -y install chkrootkit; fi && echo $'\n    [+] Scanning with chkrootkit...' &&
chkrootkit
esac

# Third scanner
read -p "  [?] Scan with rkhunter? (y/n) " choice
case "$choice" in
y|Y ) if ! dpkg -s rkhunter >/dev/null 2>&1; then echo "    [+] Installing rkhunter..." &&
apt-get -qq -y install rkhunter; fi && echo $'\n    [+] Scanning with rkhunter...' &&
rkhunter -c
esac



