#!/bin/bash

echo $'\n[>] Networking'

#-|---------- Network Interface -----------|-

cat data/references/interfaces > /etc/network/interfaces
read -p '      [+] Please enter the desired ip address: ' ip
sed -i "s/64.39.3.000/$ip/g" /etc/network/interfaces
echo "  [+] Network interface configured"


#-|-------------- DNS resolv --------------|-

echo -e 'search team1.isucdc.com\nnameserver 199.100.16.100' >> /etc/resolv.conf
echo "  [+] DNS configured"


#-|------------- Proxy Config -------------|-

echo -e 'export http_proxy="http://199.100.16.100:3128"\nexport https_proxy=$http_proxy\nexport ftp_proxy=$http_proxy' >> /etc/profile
echo 'Acquire::http { Proxy "http://apt-cache.isucdc.net:3142"; };' > /etc/apt/apt.conf.d/cache
echo "  [+] Proxy settings configured"


#-|-------------- Hosts File --------------|-

echo '127.0.0.1' $HOSTNAME >> data/references/hosts
cp /etc/hosts data/backup_files/hosts.backup
cat data/references/hosts > /etc/hosts
echo "  [+] Cleaned hosts file."


#-|-------------- SSHD Config --------------|-

cp /etc/ssh/ssh_config data/backup_files/ssh_config.backup
cat data/references/ssh_config > /etc/ssh/ssh_config

cp /etc/ssh/sshd_config data/backup_files/sshd_config.backup
cat data/references/sshd_config > /etc/ssh/sshd_config

chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
echo "  [+] Secured ssh settings."


#-|-------------- Firewall --------------|-

if ! dpkg -s ufw >/dev/null 2>&1; then 
    echo "    [+] Installing ufw..."
    apt -qq -y install ufw >/dev/null 2>&1
fi

read -p '      [+] Please enter valid critical services: ' -a critical
printf '%s\n' "${critical[@]}" >> data/critical_services
sed -i '/^\s*$/d' data/critical_services

echo "y" | ufw reset >/dev/null
ufw default deny >/dev/null 2>&1
ufw logging on >/dev/null 2>&1

service="$(cat data/critical_services | awk -F: '{ print $1 }')"
for i in $service; do
	ufw allow $service >/dev/null 2>&1
	if [ "$service" = "SSH" ]; then
		ufw limit SSH >/dev/null 2>&1
	fi
done
ufw enable >/dev/null 2>&1
echo "  [+] Firewall configured."


#-|-------------- Miscellaneous Network Settings --------------|-

echo "  [+] SYN cookie protection enabled."
echo "  [+] IPv6 Disabled."
echo "  [+] Routing Disabled."
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
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0" >> /etc/sysctl.conf

sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1
sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1
sysctl -w net.ipv4.conf.default.send_redirects=0 >/dev/null 2>&1
sysctl -w net.ipv4.conf.all.accept_source_route=0 >/dev/null 2>&1
sysctl -w net.ipv4.conf.default.accept_source_route=0 >/dev/null 2>&1
sysctl -w net.ipv4.conf.all.accept_redirects=0 >/dev/null 2>&1
sysctl -w net.ipv4.conf.default.accept_redirects=0 >/dev/null 2>&1
sysctl -w net.ipv4.conf.all.secure_redirects=0 >/dev/null 2>&1
sysctl -w net.ipv4.conf.default.secure_redirects=0 >/dev/null 2>&1
sysctl -w net.ipv4.conf.all.log_martians=1 >/dev/null 2>&1
sysctl -w net.ipv4.conf.default.log_martians=1 >/dev/null 2>&1
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1 >/dev/null 2>&1
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1 >/dev/null 2>&1
sysctl -w net.ipv4.conf.all.rp_filter=1 >/dev/null 2>&1
sysctl -w net.ipv4.conf.default.rp_filter=1 >/dev/null 2>&1
sysctl -w net.ipv4.tcp_syncookies=1 >/dev/null 2>&1
sysctl -w net.ipv4.route.flush=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1
sysctl -w net.ipv6.conf.all.accept_ra=0 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.accept_ra=0 >/dev/null 2>&1
sysctl -w net.ipv6.conf.all.accept_redirects=0 >/dev/null 2>&1
sysctl -w net.ipv6.conf.default.accept_redirects=0 >/dev/null 2>&1
sysctl -w net.ipv6.route.flush=1 >/dev/null 2>&1

#-|-------------- Disable Uncommon Protocols --------------|-

echo "  [+] Disabling uncommon network protocols..."
echo "install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install telnet /bin/true
install tipc /bin/true" >> /etc/modprobe.d/CIS.conf

#TO-DO: monitor el open connections
#TO-DO: use tcpdump
#TO-DO: make apache2, wordpress, mysql reference files.
