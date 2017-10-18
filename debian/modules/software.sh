#!/bin/bash

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
  y|Y ) apt -y update && apt -y upgrade && apt dist-upgrade && apt -y install firefox && echo "  [+] System upgraded.";;
esac


# Check for updates daily
if ! grep -q "APT::Periodic::Update-Package-Lists \"1\";" /etc/apt/apt.conf.d/10periodic; then
    sed -i 's/APT::Periodic::Update-Package-Lists "0";/APT::Periodic::Update-Package-Lists "1";/g' /etc/apt/apt.conf.d/10periodic
    echo "  [+] Daily updates configured."
fi


#-|------------------ Scans -----------------|-

# First scanner
read -p "  [?] Scan with lynis? (y/n) " choice
case "$choice" in
y|Y ) if ! dpkg -s lynis >/dev/null 2>&1; then echo "    [+] Installing lynis..." &&
apt -qq -y install lynis; fi && echo $'\n    [+] Scanning with lynis...' &&
lynis -Q
esac

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
apt -qq -y install rkhunter; fi && echo $'\n    [+] Scanning with rkhunter...' &&
rkhunter -c
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
