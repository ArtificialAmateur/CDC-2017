#!/bin/bash

echo $'\n[>] Users'

#-|--------------- Add accounts  ---------------|-

input_accounts(){
    # Clear valid_admins and valid_users
    echo '' > data/valid_admins
    echo '' > data/valid_users

    read -p '      [+] Please enter the valid admins: ' -a admins
    printf '%s\n' "${admins[@]}" >> data/valid_admins
    sed -i '/^\s*$/d' data/valid_admins
    read -p '      [+] Please enter the valid standard users: ' -a users
    printf '%s\n' "${users[@]}" >> data/valid_users
    sed -i '/^\s*$/d' data/valid_users
    cat data/valid_admins >> data/valid_users
}

create_accounts(){
    # Get valid users
    val_users="$(cat data/valid_users | awk -F: '{ print $1 }')"

    for i in $val_users; do
        if ! grep -Fqs "$i" '/etc/passwd'; then
            echo "      [+] Adding user $i...: "
	    useradd -m -s /bin/bash $i
	    echo "  [?] Enter pasword for $i: "
	    passwd $i
	
        fi
    done
}

escalate_accounts(){
    # Add users to sudoers group
    val_admins="$(cat data/valid_admins | awk -F: '{ print $1 }')"

    for i in $val_admins; do
        if ! id -nG "$i" | grep -qw "sudo"; then
            usermod -a -G sudo $i
        fi
    done
}

read -p "  [?] Add valid admins and users? (y/n) " choice
case "$choice" in 
  y|Y ) input_accounts && create_accounts && escalate_accounts;;
esac


#-|-------------- Lock root account --------------|-

if ! passwd -S | grep -q "root L"; then
    echo "root:"'$1$FvmieeAj$cDmFLn5RvjYphj3iL1RJZ/' | chpasswd -e
    passwd -l root 2>&1>/dev/null
    sed -i "s|root:x:0:0:root:/root:/bin/bash|root:x:0:0:root:/root:/sbin/nologin|g" /etc/passwd
    echo > /etc/securetty
    echo "  [+] Root account locked."
fi


#-|-------------- sudoers Config --------------|-

cp /etc/sudoers data/backup_files/sudoers.backup
cat data/references/sudoers > /etc/sudoers
echo "  [+] Sudoers file secured."


#-|-------------- Password Policy --------------|-

if ! dpkg -s libpam-cracklib >/dev/null 2>&1; then
    echo "  [+] Installing libpam-cracklib..." &&
    apt -qq -y install libpam-cracklib >/dev/null 2>&1
fi

echo "session optional pam_umask.so" >> /etc/pam.d/common-session

cp /etc/login.defs data/backup_files/login.defs.backup
cat data/references/login.defs > /etc/login.defs

cp /etc/pam.d/common-password data/backup_files/common-password.backup
cat data/references/common-password > /etc/pam.d/common-password

cp /etc/pam.d/common-auth data/backup_files/common-auth.backup
cat data/references/common-auth > /etc/pam.d/common-auth

echo "  [+] Password policy set."

#-|-------------- rsyslog Policy --------------|-

if ! dpkg -s rsyslog >/dev/null 2>&1; then
    echo "  [+] Installing rsyslog..." &&
    apt -qq -y install rsyslog
fi

echo "  [+] Configuring syslog..."
systemctl enable rsyslog >/dev/null 2>&1
systemctl start rsyslog >/dev/null 2>&1
# Configure Syslog
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

#-|-------------- audtid Policy --------------|-

if ! dpkg -s auditd >/dev/null 2>&1; then
    echo "  [+] Installing auditd..." &&
    apt -qq -y install auditd >/dev/null 2>&1
fi

echo "  [+] Configuring auditd..."
systemctl enable auditd >/dev/null 2>&1
systemctl start auditd >/dev/null 2>&1

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
##tlisten_port =
tlisten_queue = 5
tmax_per_addr = 1
##tclient_ports = 1024-65535
tclient_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
EOF

# Enable Auditing for Processes that Start Prior to auditd
echo 'GRUB_CMDLINE_LINUX="audit=1"' >> /etc/default/grub
update-grub >/dev/null 2>&1

# Record Events that Modify Date and Time Information
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change 
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change 
-a always,exit -F arch=b32 -S clock_settime -k time-change 
-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/audit.rules

# Record Events that Modify User/Group Information
echo "-w /etc/group -p wa -k identity 
-w /etc/passwd -p wa -k identity 
-w /etc/gshadow -p wa -k identity 
-w /etc/shadow -p wa -k identity 
-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/audit.rules

# Record Events that Modify System's Network Environment
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale 
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale 
-w /etc/issue -p wa -k system-locale 
-w /etc/issue.net -p wa -k system-locale 
-w /etc/hosts -p wa -k system-locale 
-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules

# Record Events that Modify Mandatory Access Controls
echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules

# Collect Login and Logout Events #
echo "-w /var/log/faillog -p wa -k logins 
-w /var/log/lastlog -p wa -k logins 
-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/audit.rules

# Collect Session Initiation Information
echo "-w /var/run/utmp -p wa -k session 
-w /var/log/wtmp -p wa -k session 
-w /var/log/btmp -p wa -k session" >> /etc/audit/rules.d/audit.rules

# Collect Discretionary Access Control Permission Modification Events
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules

# Collect Unsuccessful Unauthorised Access Attemps to Files
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules

# Collect Use of Privileged Commands

# Collect Successful File System Mounts
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts 
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules

# Collect File Deletion Events by User
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete 
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules

# Collect Changes to System Administration Scope
echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/audit.rules

# Collect System Administrator Actions
echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules

# Collect Kernel Module Loading and Unloading
echo "-w /sbin/insmod -p x -k modules 
-w /sbin/rmmod -p x -k modules 
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules

# Make the Audit Configuration Immutable
echo "-e 2" >> /etc/audit/rules.d/audit.rules
pkill -HUP -P 1 auditd
auditctl -e 1 &>/dev/null
echo "    [+] Audit policy set with auditd."

#TO-DO- add other rogue rule smashers
# if you get locked out, pam_tally --user=<user> --reset
# check /etc/pam.d/login vs /etc/pam.d/sshd

