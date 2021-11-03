#!/usr/bin/env bash
#This script is used for hardening purpose of Ubuntu 20.04

#for collecting the log
AUDITDIR="/tmp/$(hostname -s)_audit"
TIME="$(date +%F_%T)"
if [[ ! -d $AUDITDIR ]]
then
mkdir $AUDITDIR
fi

#Disabling the unused file system

#1.1.1 to 1.1.7 Covered


echo "Disabling Legacy Filesystems"
cat > /etc/modprobe.d/CIS.conf << "EOF"
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install vfat /bin/true
install udf /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
install usb-storage /bin/true
EOF

# 1.1.2 Ensure /tmp is configured
#1.1.3 Ensure nodev option set on /tmp partition
#1.1.4 Ensure nosuid option set on /tmp partition
#1.1.5 Ensure noexec option set on /tmp partition
findmnt -n /tmp 2> /dev/null 1>/dev/null
if [[ $? -eq 0 ]]
then
    echo "/tmp directory found" >> $AUDITDIR/section1.log
    echo "Manually add the line in fstab for /tmp" >> $AUDITDIR/section1.log
else
    cp -v /usr/share/systemd/tmp.mount /etc/systemd/system/
    echo -e "[Mount]\nWhat=tmpfs\nWhere=/tmp\nType=tmpfs\nOptions=mode=1777,strictatime,nosuid,nodev,noexec"
    systemctl daemon-reload
    systemctl --now enable tmp.mount
    echo "Manually added /tmp" >> $AUDITDIR/section1.log
fi


#1.1.6 Ensure /dev/shm is configured
#1.1.7 Ensure nodev option set on /dev/shm partition
#1.1.8 Ensure nosuid option set on /dev/shm partition
#1.1.9 Ensure noexec option set on /dev/shm partition

findmnt -n /dev/shm 2> /dev/null 1>/dev/null
if [[ $? -eq 0 ]]
then
    echo "/shm directory found" >> $AUDITDIR/section1.log
    echo "tmpfs /dev/shm tmpfs defaults,noexec,nodev,nosuid,size=2G 0 0" >> /etc/fstab
    mount -o remount,noexec,nodev,nosuid /dev/shm
    echo "Manually add the line in fstab for /shm" >> $AUDITDIR/section1.log
fi
{
echo -e "\nManual Activity \n#1.1.10 Ensure separate partition exists for /var\n#1.1.11 Ensure separate partition exists for /var/tmp"
echo -e "#1.1.12 Ensure /var/tmp partition includes the nodev option\n"
echo -e "#1.1.13 Ensure /var/tmp partition includes the nosuid option"
echo "1.1.14 Ensure /var/tmp partition includes the noexec option "
echo "1.1.15 Ensure separate partition exists for /var/log"
echo "1.1.16 Ensure separate partition exists for /var/log/audit"
echo "1.1.17 Ensure separate partition exists for /home"
echo "1.1.18 Ensure /home partition includes the nodev option"
} >>$AUDITDIR/section1.log

#1.1.22 Ensure sticky bit is set on all world-writable Directories

echo  " Ensure sticky bit is set on all world-writable Directories" >> $AUDITDIR/section1.log
df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null
if [[ "${?}" -ne 0 ]]
then
     df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'
fi

#1.1.23 Disable Automounting

if [[ $(systemctl is-enabled autofs) == "enable" ]]
then
    systemctl --now disable autofs
    apt purge autofs 2>&1 /dev/null
else
    apt purge autofs 2>&1 /dev/null
fi

#1.1.24 Disable USB storage

echo "install usb-storage /bin/true" > /etc/modprobe.d/usb_storage.conf
rmmod usb-storage


#1.3.1 Ensure AIDE is installed

apt install -y aide aide-common
aideinit
mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db

#1.3.2 Ensure filesystem integrity is regularly checked

echo -e "[Unit]\nDescription=Aide Check\n[Service]\nType=simple\nExecStart=/usr/bin/aide.wrapper --config /etc/aide/aide.conf --check\n[Install]\nWantedBy=multi-user.target" > /etc/systemd/system/aidecheck.service
echo -e "[Unit]\nDescription=Aide check every day at 5AM\n[Timer]\nOnCalendar=*-*-* 05:00:00\nUnit=aidecheck.service\n[Install]\nWantedBy=multi-user.target" >> /etc/systemd/system/aidecheck.timer
chown root:root /etc/systemd/system/aidecheck.*
chmod 0644 /etc/systemd/system/aidecheck.*
systemctl daemon-reload
systemctl enable aidecheck.service
systemctl --now enable aidecheck.timer

#1.4.1 Ensure permissions on bootloader config are not overridden
#skipping

#1.4.3 Ensure permissions on bootloader config are configured

chown root:root /boot/grub/grub.cfg
chmod u-wx,go-rwx /boot/grub/grub.cfg

#1.4.4 Ensure authentication required for single user mode
echo "root:P@ssw0rd@123" | chpasswd

#1.5.2 Ensure address space layout randomization (ASLR) is enabled
for file in /etc/sysctl.conf /etc/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /run/sysctl.d/*.conf; do
 if [ -f "$file" ]; then
 grep -Esq "^\s*kernel\.randomize_va_space\s*=\s*([0-1]|[3-9]|[1-9][0-9]+)" "$file" && sed -ri 's/^\s*kernel\.randomize_va_space\s*=\s*([0-1]|[3-9]|[1-9][0-9]+)/# &/gi' "$file"
 fi
done
sysctl -w kernel.randomize_va_space=2

#1.5.3 Ensure prelink is not installed

apt purge prelink 2>&1 /dev/null

#1.5.4 Ensure core dumps are restricted

echo -e "* hard core 0\nfs.suid_dumpable = 0" >> /etc/security/limits.conf
sysctl -w fs.suid_dumpable=0


#1.6.1.1 Ensure AppArmor is installed

apt install -y apparmor 2>&1 /dev/null

#1.6.1.2 Ensure AppArmor is enabled in the bootloader configuration
echo "GRUB_CMDLINE_LINUX=\"apparmor=1 security=apparmor\"" >> /etc/default/grub
update-grub

#1.6.1.3 Ensure all AppArmor Profiles are in enforce or complain mode
apt install apparmor-utils -y 2>&1 /dev/null
aa-enforce /etc/apparmor.d/*

echo "Creating Banner..."
sed -i "s/\#Banner none/Banner \/etc\/issue\.net/" /etc/ssh/sshd_config
cp -p /etc/issue.net $AUDITDIR/issue.net_$TIME.bak
cat > /etc/issue.net << 'EOF'
/------------------------------------------------------------------------\
|                       *** NOTICE TO USERS ***                          |
|                                                                        |
| This computer system is the private property of Reserve Bank           |
| Information Technology Pvt Ltd. It is for authorized use only.         |
|                                                                        |
| Users (authorized or unauthorized) have no explicit or implicit        |
| expectation of privacy.                                                |
|                                                                        |
| Any or all uses of this system and all files on this system may be     |
| intercepted, monitored, recorded, copied, audited, inspected, and      |
| disclosed to your employer, to authorized site, government, and law    |
| enforcement personnel, as well as authorized officials of government   |
| agencies, both domestic and foreign.                                   |
|                                                                        |
| By using this system, the user consents to such interception,          |
| monitoring, recording, copying, auditing, inspection, and disclosure   |
| at the discretion of such personnel or officials.  Unauthorized or     |
| improper use of this system may result in civil and criminal penalties |
| and administrative or disciplinary action, as appropriate. By          |
| continuing to use this system you indicate your awareness of and       |
| consent to these terms and conditions of use. LOG OFF IMMEDIATELY if   |
| you do not agree to the conditions stated in this warning.             |
\------------------------------------------------------------------------/
EOF
cp -p /etc/motd /etc/motd_$TIME.bak
cat > /etc/motd << 'EOF'
Reserve Bank Information Technology Pvt Ltd
EOF
rm -rf /etc/issue
ln -s /etc/issue.net /etc/issue


#1.7.4 Ensure permissions on /etc/motd are configured (Automated)
chown root:root $(readlink -e /etc/motd)
chmod u-x,go-wx $(readlink -e /etc/motd)

#1.7.5 Ensure permissions on /etc/issue are configured
chown root:root $(readlink -e /etc/issue)
chmod u-x,go-wx $(readlink -e /etc/issue)

#1.7.6 Ensure permissions on /etc/issue.net are configured
chown root:root $(readlink -e /etc/issue.net)
chmod u-x,go-wx $(readlink -e /etc/issue.net)

echo -e "[org/gnome/login-screen]\nbanner-message-enable=true\nbanner-message-text='Reserver Bank Information Technology Pvt Ltd property. Authorized uses only. All activity may be monitored and reported'.\ndisable-user-list=true" >  /etc/gdm3/greeter.dconf-defaults

apt -s upgrade
apt upgrade -y


############################################################
###Section 2

#2.1.1.1 Ensure time synchronization is in use (Automated)

if [[ $(systemctl is-enabled systemd-timesyncd) == "enabled" ]]
then
    apt purge ntp
    apt purge chron
    echo -e "0.NTP=172.16.32.60 1.debian.pool.ntp.org\nFallbackNTP=2.debian.pool.ntp.org 3.debian.pool.ntp.org #Servers listed\nRootDistanceMax=1" >> /etc/systemd/timesyncd.conf
fi
systemctl start systemd-timesyncd.service
timedatectl set-ntp true
#2.1.2 Ensure X Window System is not installed (Automated) Not Impelemented

#2.1.3 Ensure Avahi Server is not installed (Automated)

echo "Disabling Unnecessary Services..."
servicelist=( dovecot-imapd dovecot-pop3d ldap-utils slpd dhcpd avahi-daemon snmpd nfs-kernel-server bind9 vsftpd apache2 cups samba squid rsync nis rsh-client talk telnet rpcbind )
for i in ${servicelist[@]}; do
  [ $(systemctl stop $i 2> /dev/null) ] || echo "$i is stopped"
  [ $(systemctl disable $i 2> /dev/null) ] || echo "$i is Disabled"
  [ $(apt-get remove --purge $i 2> /dev/null) ]  || echo "$i is removed"
done

##################################################################################################
#Section 3

#3 Network configuration

#3.1.1 Disable IPv6
#3.1.2 Ensure wireless interfaces are disabled (Automated)
nmcli radio all off
#3.2 Network Parameters (Host Only)
cat > /etc/sysctl.d/99-CIS.conf << 'EOF'
net.ipv4.ip_forward=0
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
net.ipv4.route.flush=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.icmp_echo_bold_ignore_broadcasts=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.disable_ipv6=1
fs.suid_dumpable=0
EOF

#3.4 Uncommon Network Protocols
{
echo "install dccp /bin/true"
echo "install sctp /bin/true"
echo "install rds /bin/true"
echo "install tipc /bin/true"
} >/etc/modprobe.d/other_Services.conf

#3.5 Firewall configuration
apt install ufw -y
apt purge iptables-persistent
#apt install nftables -y

###############################
#4 Logging and Auditing system

#4.1 Configure System Accounting (auditd)
apt install auditd audispd-plugins -y
systemctl is-enabled auditd
systemctl --now enable auditd

echo -e "GRUB_CMDLINE_LINUX=\"audit=1\"" >> /etc/default/grub
echo -e "GRUB_CMDLINE_LINUX=\"audit_backlog_limit=8192\"" >> /etc/default/grub
update-grub

cp -a /etc/audit/auditd.conf /etc/audit/auditd.conf.bak
sed -i 's/^space_left_action.*$/space_left_action = email/' /etc/audit/auditd.conf
sed -i 's/^action_mail_acct.*$/action_mail_acct = root/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action.*$/admin_space_left_action = halt/' /etc/audit/auditd.conf
sed -i 's/^max_log_file_action.*$/max_log_file_action = keep_logs/' /etc/audit/auditd.conf

echo "Setting audit rules..."
cat > /etc/audit/rules.d/CIS.rules << "EOF"
-D
-b 320
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k session
-w /var/log/btmp -p wa -k session
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-w /etc/sudoers -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-w /etc/selinux/ -p wa -k MAC-policy
-e 2
EOF
echo "Generating audit rules..."
augenrules
echo "Enabling auditd service..."
systemctl enable auditd


apt install rsyslog -y
systemctl --now enable rsyslog.service
systemctl start rsyslog.service


echo "Generating additional logs..."
{
echo 'auth /var/log/secure'
echo 'kern.* /var/log/messages'
echo 'daemon.* /var/log/messages'
echo 'syslog.* /var/log/messages'
} > /etc/rsyslog.d/CIS.conf

chmod 600 /etc/rsyslog.d/CIS.conf

echo "Setting journald configuration"
for i in \
"Compress=yes" \
"ForwardToSyslog=yes" \
"Storage=persistent" \
; do
  [[ `grep -q "^$i" /etc/systemd/journald.conf` ]] && continue
  option=${i%%=*}
  if [[ `grep "${option}" /etc/systemd/journald.conf` ]]; then
    sed -i "s/.*${option}.*/$i/g" /etc/systemd/journald.conf
  else
    echo "${i}" >> /etc/systemd/journald.conf
  fi
done

find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-w,o-rwx "{}" +
sed  -i 's/^create/create 0640 root utmp/g' /etc/logrotate.conf

#################################################
#5 Access, Authentication and Authorization

systemctl --now enable cron

for i in anacrontab crontab cron.hourly cron.daily cron.weekly cron.monthly cron.d; do
  chown root:root /etc/$i
  chmod og-rwx  /etc/$i
done


echo "Handle At and Cron Allow Files..."
for file in at cron; do
  touch /etc/${file}.allow
  chown root:root /etc/${file}.allow
  chmod g-wx,o-rwx /etc/${file}.allow
  rm -rf /etc/${file}.deny
done



apt install sudo -y
{
echo "Defaults use_pty"
echo "Defaults logfile=\"/var/log/sudo.log\""
} >> /etc/sudoers

echo "Configuring SSH..."
cp /etc/ssh/sshd_config $AUDITDIR/sshd_config_$TIME.bak
for i in \
"LogLevel INFO" \
"Protocol 2" \
"X11Forwarding no" \
"MaxAuthTries 4" \
"IgnoreRhosts yes" \
"HostbasedAuthentication no" \
"PermitRootLogin no" \
"PermitEmptyPasswords no" \
"PermitUserEnvironment no" \
"ClientAliveInterval 300" \
"ClientAliveCountMax 0" \
"LoginGraceTime 60" \
"UsePAM yes" \
"MaxStartups 10:30:60" \
"AllowTcpForwarding no" \
"Ciphers aes128-ctr,aes192-ctr,aes256-ctr" \
; do
  [[ `egrep -q "^${i}" /etc/ssh/sshd_config` ]] && continue
  option=${i%% *}
  grep -q ${option} /etc/ssh/sshd_config && sed -i "s/.*${option}.*/$i/g" /etc/ssh/sshd_config || echo "$i" >> /etc/ssh/sshd_config
done


chown root:root /etc/ssh/sshd_config
chmod og-rwx /etc/ssh/sshd_config

find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod u-x,go-rwx {} \;

find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod u-x,go-wx {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;
#echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-256,hmac-sha2-512" >> /etc/ssh/sshd_config

#echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" >> /etc/ssh/sshd_config
sed  -i 's/ClientAliveCountMax 0/ClientAliveCountMax 3/g' /etc/ssh/sshd_config

echo "Creating Banner..."
sed -i "s/\#Banner none/Banner \/etc\/issue\.net/" /etc/ssh/sshd_config
cp -p /etc/issue.net $AUDITDIR/issue.net_$TIME.bak
cat > /etc/issue.net << 'EOF'
/------------------------------------------------------------------------\
|                       *** NOTICE TO USERS ***                          |
|                                                                        |
| This computer system is the private property of Reserve Bank           |
| technology Pvt Ltd.It is for authorized use only.                                         |
|                                                                        |
| Users (authorized or unauthorized) have no explicit or implicit        |
| expectation of privacy.                                                |
|                                                                        |
| Any or all uses of this system and all files on this system may be     |
| intercepted, monitored, recorded, copied, audited, inspected, and      |
| disclosed to your employer, to authorized site, government, and law    |
| enforcement personnel, as well as authorized officials of government   |
| agencies, both domestic and foreign.                                   |
|                                                                        |
| By using this system, the user consents to such interception,          |
| monitoring, recording, copying, auditing, inspection, and disclosure   |
| at the discretion of such personnel or officials.  Unauthorized or     |
| improper use of this system may result in civil and criminal penalties |
| and administrative or disciplinary action, as appropriate. By          |
| continuing to use this system you indicate your awareness of and       |
| consent to these terms and conditions of use. LOG OFF IMMEDIATELY if   |
| you do not agree to the conditions stated in this warning.             |
\------------------------------------------------------------------------/
EOF
cp -p /etc/motd /etc/motd_$TIME.bak
cat > /etc/motd << 'EOF'
Reserve Bank Information Technology Pvt Ltd AUTHORIZED USE ONLY
EOF
rm -rf /etc/issue
ln -s /etc/issue.net /etc/issue
apt install libpam-pwquality -y
echo "Setting Password Quality policies..."
for i in \
"minlen = 14" \
"dcredit = -1" \
"ucredit = -1" \
"ocredit = -1" \
"lcredit = -1" \
"retry = 3" \
; do
  [[ `grep -q "^$i" /etc/security/pwquality.conf` ]] && continue
  option=${i%%=*}
  if [[ `grep -q "${option}" /etc/security/pwquality.conf` ]]; then
    sed -i "s/.*${option}.*/$i/g" /etc/security/pwquality.conf
  else
    echo "${i}" >> /etc/security/pwquality.conf
  fi
done

cp etc/pam.d/common-auth etc/pam.d/common-auth_bkp
echo -e "account requisite pam_deny.so\naccount required  pam_tally2.so" >> /etc/pam.d/common-auth
echo -e "account requisite pam_deny.so\naccount required  pam_tally2.so" >> /etc/pam.d/common-auth

echo -e "password required pam_pwhistory.so remember=5" >> /etc/pam.d/common-password
sed  -i 's/obscure//g' /etc/pam.d/common-password

echo "Set login.defs..."
for i in \
"PASS_MAX_DAYS 90" \
"PASS_MIN_DAYS 7" \
"PASS_WARN_AGE 7" \
; do
  [[ `egrep "^${i}" /etc/login.defs` ]] && continue
  option=${i%% *}
  grep -q ${option} /etc/login.defs && sed -i "s/.*${option}.*/$i/g" /etc/login.defs || echo "$i" >> /etc/login.defs
done


cho "Locking inactive user accounts..."
useradd -D -f 30

usermod -g 0 root
echo "umask 027" >>/etc/profile.d/set_umask.sh
echo -e "readonly TMOUT=900 ; export TMOUT" >> /etc/profile.d/TMOUT.sh

echo "Restricting Access to the su Command..."
cp /etc/pam.d/su cp /etc/pam.d/su_bkp
pam_su='/etc/pam.d/su'
line_num="$(grep -n "^\#auth[[:space:]]*required[[:space:]]*pam_wheel.so[[:space:]]*use_uid" ${pam_su} | cut -d: -f1)"
sed -i "${line_num} a auth              required        pam_wheel.so use_uid" ${pam_su}
###################################################
#Section 6

servicelist=(passwd  passwd- group group-)
for i in ${servicelist[@]}; do
  chown root:root /etc/$i
  chmod u-x,go-wx /etc/$i
done

servicelist=(shadow shadow- gshadow gshadow-))
for i in ${servicelist[@]}; do
  chown root:root /etc/$i
  chmod u-x,g-wx,o-rwx  /etc/$i
done

echo "Searching for world writable files.."

df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 >> $AUDITDIR/world_writable_files_$TIME.log

cho "Searching for Un-owned files and directories..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls >> $AUDITDIR/unowned_files_$TIME.log

#34: Find Un-grouped Files and Directories
echo "Searching for Un-grouped files and directories..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls >> $AUDITDIR/ungrouped_files_$TIME.log

echo "Searching for SUID System Executables..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print >> $AUDITDIR/suid_exec_$TIME.log

echo "Searching for SGID System Executables..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print >> $AUDITDIR/sgid_exec_$TIME.log

echo "Searching for empty password fields..."
/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print $1 " does not have a password "}' >> $AUDITDIR/empty_passwd_$TIME.log


echo "Reviewing User and Group Settings..."
echo "Reviewing User and Group Settings..." >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/passwd >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/shadow >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/group >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }' >> $AUDITDIR/reviewusrgrp_$TIME.log

echo "Checking That Defined Home Directories Exist..."

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
 if [ $uid -ge 1000 -a -d "$dir" -a $user != "nfsnobody" ]; then
 owner=$(stat -L -c "%U" "$dir")
 if [ "$owner" != "$user" ]; then
 echo "The home directory $dir of user $user is owned by $owner." >> $AUDITDIR/audit_$TIME.log
 fi
 fi
done


echo "Checking That Users Are Assigned Home Directories..."

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
  if [ $uid -ge 1000 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
 echo "The home directory $dir of user $user does not exist." >> $AUDITDIR/audit_$TIME.log
 fi
done

echo "Checking User Dot File Permissions..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |
/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.[A-Za-z0-9]*; do

        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`

            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]; then
                echo "Group Write permission set on file $file" >> $AUDITDIR/dotfile_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]; then
                echo "Other Write permission set on file $file" >> $AUDITDIR/dotfile_permission_$TIME.log
            fi
        fi

    done

done

echo "Checking Permissions on User .netrc Files..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.netrc; do
        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
            if [ `echo $fileperm | /bin/cut -c5 ` != "-" ]
            then
                echo "Group Read set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]
            then
                echo "Group Write set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c7 ` != "-" ]
            then
                echo "Group Execute set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c8 ` != "-" ]
            then
                echo "Other Read  set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]
            then
                echo "Other Write set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c10 ` != "-" ]
            then
                echo "Other Execute set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
        fi
    done
done

echo "Checking for Presence of User .rhosts Files..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.rhosts; do
        if [ ! -h "$file" -a -f "$file" ]; then
            echo ".rhosts file in $dir" >> $AUDITDIR/rhosts_$TIME.log
        fi    done
done

echo "Checking for Presence of User .forward Files..."

for dir in `/bin/cat /etc/passwd |\
    /bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
        echo ".forward file $dir/.forward exists"  >> $AUDITDIR/audit_$TIME.log
    fi
done


cho "Checking for Duplicate User Names..."

cat /etc/passwd | cut -f1 -d":" | sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/passwd | xargs`
        echo "Duplicate User Name $2: ${uids}"  >> $AUDITDIR/audit_$TIME.log
    fi
done
echo "Checking That Reserved UIDs Are Assigned to System Accounts..."

defUsers="root bin daemon adm lp sync shutdown halt mail news uucp operator games gopher ftp nobody nscd vcsa rpc mailnull smmsp pcap ntp dbus avahi sshd rpcuser nfsnobody haldaemon avahi-autoipd distcache apache oprofile webalizer dovecot squid named xfs gdm sabayon usbmuxd rtkit abrt saslauth pulse postfix tcpdump"
/bin/cat /etc/passwd | /bin/awk -F: '($3 < 500) { print $1" "$3 }' |\
    while read user uid; do
        found=0
        for tUser in ${defUsers}
        do
            if [ ${user} = ${tUser} ]; then
                found=1
            fi
        done
        if [ $found -eq 0 ]; then
            echo "User $user has a reserved UID ($uid)."  >> $AUDITDIR/audit_$TIME.log
        fi
    done


echo "Checking for Duplicate GIDs..."

/bin/cat /etc/group | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        grps=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate GID ($2): ${grps}" >> $AUDITDIR/audit_$TIME.log
    fi
done


echo "Checking Groups in /etc/passwd..."

for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
  grep -q -P "^.*?:x:$i:" /etc/group
  if [ $? -ne 0 ]; then
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" >> $AUDITDIR/audit_$TIME.log
  fi
done
