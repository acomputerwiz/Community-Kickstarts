##########################################################
#
# Name: secure-lockdown.sh
# Description: Modified script sourced from Kickstart file with many of the DISA STIG 
# changes applied via %post functionality
# Distro: Centos/RHEL 7 & Fedora 25+
# 
#################### End User Notes ######################
#
#   There are a number of considerations to be made when 
# using this document. Partitioning space, system use, 
# and other tasks that make servers different.
#
#
# Configure authentication to FORCE /etc/*shadow, and enable kerberos and ldap
authconfig --enableshadow --enablemd5 --enablekrb5 --enableldap  --updateall

########## UPDATE THE PACKAGE LIST #############
dnf -y install @security-lab @web-server @editors @gnome-desktop @system-tools @base-x @graphics @printing @sound-and-video @xfce-desktop 
# Packages added for security
dnf -y install aide audit vlock i3wm logwatch nmap zsh

############# Adding Security Enhancements ############################


################# User Login Security Changes #####################
# GEN000020 (G001)
# GEN000040 (G002)
# GEN000060 (G003)
# Require root password for single user mode
echo "Locking down GEN000020, GEN000040, GEN000060"
echo "Require the root pw when booting into single user mode" >> /usr/lib/systemd/systemd-initctl
echo "~~:S:wait:/sbin/sulogin" >> /usr/lib/systemd/systemd-initctl
echo "GEN000020, GEN000040,GEN000060 Complete"

## Prevent entering interactive boot
echo 'PROMPT=no' >> /etc/sysconfig/init
echo "Interactive Boot disabled"

# LNX00580 (L222)
echo "Locking down LNX00580"
perl -npe 's/ca::ctrlaltdel:\/sbin\/shutdown/#ca::ctrlaltdel:\/sbin\/shutdown/' -i /usr/lib/systemd/systemd-initctl
echo "LNX00580 Complete"


# We'll get to the updated versions once we configure pam.

# GEN000700
# Change the password expiration time,expiry warning time from undefined to 60 days
echo "Locking down GEN000700"
perl -npe 's/PASS_MAX_DAYS\s+99999/PASS_MAX_DAYS 60/' -i /etc/login.defs
chage -M 60 root
chage -W 7 root
chage -M 45 linuxmodder
chage -W 7 linuxmodder
echo "GEN000700 Complete"

# GEN000540
# Ensure that the user cannot change their password more than once a day.
echo "Locking down GEN000540"
perl -npe 's/PASS_MIN_DAYS\s+0/PASS_MIN_DAYS 1/g' -i /etc/login.defs
echo "GEN000540 Complete"

# GEN000480 (G015)
echo "Locking down GEN000480"
echo "Make the user waits four seconds if they fail after LOGIN_RETRIES" >> /etc/login.defs
echo "FAIL_DELAY 4" >> /etc/login.defs
echo "GEN000480 Complete"

# GEN000820
echo "Locking down GEN000820"
perl -npe 's/PASS_MIN_LEN\s+5/PASS_MIN_LEN  20/' -i /etc/login.defs
#STIG specifies using foloowing, but it's not a valid parameter
echo "GEN000820 Complete"

## Since RHEL/CentOS 5.3, authconfig supports SHA password encryption
## This cannot be set by default using auth earlier in the KS, so it must be done in %post
echo "Using SHA512 for the password algorithm"
authconfig --passalgo=sha512 --updateall
echo "Done"

###### PAM Modifications
# These modifications apply to GEN000460, GEN000600 and GEN000620
touch /var/log/tallylog
# for Centos 7.1 may need to create /etc/pam.d/system-auth-local as well
cat << 'EOF' > /etc/pam.d/system-auth-local
#%PAM-1.0
# Auth Section
auth sufficient pam_yubico.so mode=challenge-response
auth required pam_tally2.so unlock_time=900 onerr=fail no_magic_root
auth required pam_faildelay.so delay=5000000
auth include system-auth-ac
auth includ pam_yubico.so

# Accounts Section
account sufficient pam_yubico.so mode=challenge-response
account required pam_tally2.so
account include system-auth-ac
account include pam_yubico.so
# Password Section
password sufficient pam_yubico.so mode=challenge-response
password required pam_pwhistory.so   use_authtok remember=5 retry=3
password requisite pam_passwdqc.so min=disabled,disabled,16,12,8
password include system-auth-ac
password include pam_yubico.so

# Session Section
## By default we're only going to log what root does
## This gets really verbose if we log more.
## If you want to log everyone, remove disable=*
session sufficient pam_yubico.so mode=challenge-response
session required pam_tty_audit.so disable=* enable=root
session include system-auth-ac
session include pam_yubico.so
EOF


# Create some basic shell rules for users. 

echo "Idle users will be removed after 15 minutes"
echo "readonly TMOUT=600" >> /etc/profile.d/os-security.sh
echo "readonly HISTFILE" >> /etc/profile.d/os-security.sh
chmod +x /etc/profile.d/os-security.sh

# GEN002560
# Reset the umasks for all users to 077
echo "Locking down GEN002560"
perl -npe 's/umask\s+0\d2/umask 077/g' -i /etc/bashrc
perl -npe 's/umask\s+0\d2/umask 077/g' -i /etc/csh.cshrc
echo "GEN002560 Complete"


## Require GUI consoles to lock if idle longer than 10 minutes. 
if [ -f /etc/gconf/gconf.xml.mandatory ]; then 
  gconftool-2 --direct \
	--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
	--type bool \
	--set /apps/gnome-screensaver/idle_activation_enabled true
  gconftool-2 --direct \
	--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
	--type bool --set /apps/gnome-screensaver/lock_enabled true
  gconftool-2 --direct \
	--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
	--type string \
	--set /apps/gnome-screensaver/mode blank-only
  gconftool-2 --direct \
	--config-source xml:readwrite:/etc/gconf/gconf.xml.mandatory \
	--type int \
	--set /apps/gnome-screensaver/idle_delay 10
fi

## No one gets to run cron or at jobs unless we say so.
echo "Locking down Cron"
touch /etc/cron.allow
chmod 600 /etc/cron.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/cron.deny
echo "Locking down AT"
touch /etc/at.allow
chmod 600 /etc/at.allow
awk -F: '{print $1}' /etc/passwd | grep -v root > /etc/at.deny

# GEN000400 (G010)
echo "Locking down GEN000400"
# Set the /etc/issue file to something scary.  This one has no linefeeds, so it will wrap accordingly.
# Change this to your own banner for organizations outside the Scary Zone

cat << 'EOF' >/etc/issue
USE OF THIS COMPUTER SYSTEM, OPERATED BY AMERIDEA, REGARDLESS WHETHER AUTHORIZED OR UNAUTHORIZED CONSTITUTES CONSENT TO MONITORING OF THIS SYSTEM.  UNAUTHORIZED USE MAY SUBJECT YOU TO CRIMINAL PROSECUTION.  EVIDENCE OF UNAUTHORIZED USE COLLECTED DURING MONITORING MAY BE USED FOR ADMINISTRATIVE, CRIMINAL, OR OTHER ADVERSE ACTION.  USE OF THIS SYSTEM CONSTITUTES CONSENT TO MONITORING FOR THESE PURPOSES.
EOF
echo "GEN000400 Completed"


# The banner above works great for shell logins, but won't work for gui logins. 
if [ -f /etc/gdm/PreSession/Default ]; then
# GEN000420 (G011)
# This part creates the same login banner once your username and password has been entered.  This has linefeeds in it.
# Text needs to be cleaned up a touch.
echo "Locking down GEN000420"
perl -npe 's/exit\s0/\n/' -i /etc/gdm/PreSession/Default

cat << 'EOF' >> /etc/gdm/PreSession/Default
/usr/bin/gdialog --yesno "Agree = 'OK'   Disagree = 'Cancel'

USE OF THIS COMPUTER SYSTEM, OPERATED BY AMERIDEA, REGARDLESS WHETHER AUTHORIZED OR UNAUTHORIZED CONSTITUTES CONSENT TO MONITORING OF THIS SYSTEM.  UNAUTHORIZED USE MAY SUBJECT YOU TO CRIMINAL PROSECUTION.  EVIDENCE OF UNAUTHORIZED USE COLLECTED DURING MONITORING MAY BE USED FOR ADMINISTRATIVE, CRIMINAL, OR OTHER ADVERSE ACTION.  USE OF THIS SYSTEM CONSTITUTES CONSENT TO MONITORING FOR THESE PURPOSES.

Agree = 'OK'   Disagree = 'Cancel'"
if ( test 1 -eq $? ); then
        /usr/bin/gdialog --infobox "Logging out in 10 Seconds" 1 20 &
        sleep 10
        exit 1
fi

exit 0
EOF
echo "GEN000420 Completed"
fi
## Harden audit // git@github.com:virtadpt/rhel-hardening.git

## This file is automatically generated from /etc/audit/rules.d
-D
-b 320

# Record any changes to the system clock.
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change

# Record any alterations to the /etc/[passwd,group] files.
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Record alterations to any system or network environment files.
-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale

# Record any attempts to change the system's SElinux configuration.
-w /etc/selinux/ -p wa -k MAC-policy

# Record changes to system login/logout log files.
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Record session initiation attempts.
-w /var/run/umtp -p wa -k session
-w /var/run/wmtp -p wa -k session

# Record changes to Discretionary Access Control settings.
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod

# Record failed attempts to access files.
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access

# Audit attempts to mount file systems.
-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts

# Audit file deletion.
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete

# Note changes to users' scope that elevate privileges.
-w /etc/sudoers -p wa -k scope

# Monitor sudo logs.
-w /var/log/sudo.log -p wa -k actions
-w /var/log/sudo-io/ -p wa -k actions

# Audit loading and unloading of kernel modules.
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
EOF

## Harden auditd now 
cat << EOF > /etc/audit/auditd.conf
#
# This file controls the configuration of the audit daemon
#

log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root
priority_boost = 4
flush = INCREMENTAL
freq = 20

# The maximum number of audit logs to store at any one time is 99.  That should
# give us time to migrate them off-system.
num_logs = 99

disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE

# The maximum audit logfile size, in megabytes.
max_log_file = 50

# When the current audit log reaches its maximum size, rotate it.
max_log_file_action = ROTATE

# When the local storage array is down to a gig, panic.  E-mail the root user.
space_left = 1024
space_left_action = email
action_mail_acct = root

# When the local storage array is down to half a gig, panic harder.  Suspend
# audit logging until we get things sorted out.
admin_space_left = 512
admin_space_left_action = suspend

# When the local storage array is out of disk space, stop auditing.
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

################## File and Directory Security #########################

# Restrict mount points with noexec, nosuid, and nodev where applicable

# GEN002420
echo "Locking down GEN002420"
FSTAB=/etc/fstab
SED=/bin/sed

#nosuid on /home
if [ $(grep "[[:blank:]]\/home[[:blank:]]" ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
        MNT_OPTS=$(grep "[[:blank:]]\/home[[:blank:]]" ${FSTAB} | awk '{print $4}')
        ${SED} -i "s/\([[:blank:]]\/home.*${MNT_OPTS}\)/\1,nosuid/" ${FSTAB}
fi

# nosuid on /sys
if [ $(grep "[[:blank:]]\/sys[[:blank:]]" ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
        MNT_OPTS=$(grep "[[:blank:]]\/sys[[:blank:]]" ${FSTAB} | awk '{print $4}')
        ${SED} -i "s/\([[:blank:]]\/sys.*${MNT_OPTS}\)/\1,nosuid/" ${FSTAB}
fi

## nosuid on /boot
if [ $(grep "[[:blank:]]\/boot[[:blank:]]" ${FSTAB} | grep -c "nosuid") -eq 0 ]; then
        MNT_OPTS=$(grep "[[:blank:]]\/boot[[:blank:]]" ${FSTAB} | awk '{print $4}')
        ${SED} -i "s/\([[:blank:]]\/boot.*${MNT_OPTS}\)/\1,nosuid/" ${FSTAB}
fi

# nodev on /usr
if [ $(grep "[[:blank:]]\/usr[[:blank:]]" ${FSTAB} | grep -c "nodev") -eq 0 ]; then
        MNT_OPTS=$(grep "[[:blank:]]\/usr[[:blank:]]" ${FSTAB} | awk '{print $4}')
       ${SED} -i "s/\([[:blank:]]\/usr.*${MNT_OPTS}\)/\1,nodev/" ${FSTAB}
fi

#nodev on /home
if [ $(grep "[[:blank:]]\/home[[:blank:]]" ${FSTAB} | grep -c "nodev") -eq 0 ]; then
        MNT_OPTS=$(grep "[[:blank:]]\/home[[:blank:]]" ${FSTAB} | awk '{print $4}')
        ${SED} -i "s/\([[:blank:]]\/home.*${MNT_OPTS}\)/\1,nodev/" ${FSTAB}
fi

# nodev on /usr/local
if [ $(grep "[[:blank:]]\/usr/local[[:blank:]]" ${FSTAB} | grep -c "nodev") -eq 0 ]; then
        MNT_OPTS=$(grep "[[:blank:]]\/usr/local[[:blank:]]" ${FSTAB} | awk '{print $4}')
        ${SED} -i "s/\([[:blank:]]\/usr\/local.*${MNT_OPTS}\)/\1,nodev/" ${FSTAB}
fi

# nodev and noexec on /tmp
if [ $(grep "[[:blank:]]\/tmp[[:blank:]]" ${FSTAB} | grep -c "nodev") -eq 0 ]; then
        MNT_OPTS=$(grep "[[:blank:]]\/tmp[[:blank:]]" ${FSTAB} | awk '{print $4}')
        ${SED} -i "s/\([[:blank:]]\/tmp.*${MNT_OPTS}\)/\1,nodev,noexec/" ${FSTAB}
fi
# nodev and noexec on /var/tmp
if [ $(grep "[[:blank:]]\/var/tmp[[:blank:]]" ${FSTAB} | grep -c "nodev") -eq 0 ]; then
        MNT_OPTS=$(grep "[[:blank:]]\/tmp[[:blank:]]" ${FSTAB} | awk '{print $4}')
        ${SED} -i "s/\([[:blank:]]\/var/tmp.*${MNT_OPTS}\)/\1,nodev,noexec/" ${FSTAB}
fi

# nodev on /var
if [ $(grep "[[:blank:]]\/var[[:blank:]]" ${FSTAB} | grep -c "nodev") -eq 0 ]; then
       MNT_OPTS=$(grep "[[:blank:]]\/var[[:blank:]]" ${FSTAB} | awk '{print $4}')
        ${SED} -i "s/\([[:blank:]]\/var.*${MNT_OPTS}\)/\1,nodev/" ${FSTAB}
fi

echo "GEN002420 Complete"

# By default  /root has permissions of 750. Change this to 700
# GEN000920 (G023)
echo "Locking down GEN000920"
# Correct the permissions on /root to a DISA allowed 700
chmod 700 /root
echo "GEN000920 Complete"

# GEN002680 (G094)
# reset permissions on audit logs
echo "Locking down GEN002680"
chmod 700 /var/log/audit
chmod 600 /var/log/audit/*
echo "GEN002680 Complete"

# GEN003080
echo "Locking down GEN003080"
chmod 600 /etc/crontab
chmod 700 /usr/share/logwatch/scripts/logwatch.pl
echo "GEN003080 Complete"

# GEN003520 ( RHEL5 default anyway )
echo "Locking down GEN003520"
chmod 700 /var/crash
chown -R root.root /var/crash
echo "GEN003520 Complete"

# GEN006520
echo "Locking down GEN006520"
chmod 740 /etc/rc.d/init.d/iptables
chmod 740 /sbin/iptables
chmod 740 /usr/share/logwatch/scripts/services/iptables
echo "GEN006520 Complete"

# GEN001560
echo "Locking down GEN001560"
chmod -R 700 /etc/skel
echo "GEN001560 Complete"

# GEN005400 (G656)
# Reset the permissions to a DISA-blessed rw-r-----
echo "Locking down GEN005400"
chmod 640 /etc/syslog.conf
echo "GEN005400 Complete"

# LNX00440 (L046)
# Set mode to DISA-blessed rw-r------
echo "Locking down LNX00440"
chmod 640 /etc/security/access.conf
echo "LNX00440 Complete"

# GEN001260
echo "Locking down GEN001260"
perl -npe 's%chmod 0664 /var/run/utmp /var/log/wtmp%chmod 0644 /var/run/utmp /var/log/wtmp%g' -i /etc/systemd/system.conf
echo "GEN001260"

# LNX00520 (L208)
echo "Locking down LNX00520"
chmod 600 /etc/sysctl.conf
echo "LNX00520 Complete"

# Add some enhancements to sysctl
cat << 'EOF' >> /etc/sysctl.conf
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.tcp_max_syn_backlog = 1280
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_timestamps = 0
kernel.exec-shield = 1
kernel.randomize_va_space = 1
EOF

########## Turn off the uneeded stuff #############
# IAVA0410 (G592) and GEN003700
# Turn off unneeded services
# You may want to leave sendmail enabled but the STIG says otherwise
# I mark this as mitigated by the firewall, and not accepting outside
# connections. The NSA RHEL5 guide has a full service list 
# with recommendations
echo "Locking down IAVA0410 and GEN003700"
/sbin/chkconfig bluetooth off
/sbin/chkconfig irda off
/sbin/chkconfig lm_sensors off
/sbin/chkconfig portmap off
/sbin/chkconfig rawdevices off
#/sbin/chkconfig rpcgssd off
#/sbin/chkconfig rpcidmapd off
#/sbin/chkconfig rpcsvcgssd off
#/sbin/chkconfig sendmail off
/sbin/chkconfig xinetd off
/sbin/chkconfig kudzu off
echo "IAVA0410 and GEN003700 Complete"

######### Remove useless users ##############
# This isn't strictly needed as they have a default shell of nologin
# but we're removing them anyway to be safe.

echo "Locking down LNX0034 and GEN004840"
/usr/sbin/userdel shutdown
/usr/sbin/userdel halt
/usr/sbin/userdel games
/usr/sbin/userdel operator
/usr/sbin/userdel ftp
/usr/sbin/userdel news
/usr/sbin/userdel gopher
echo "LNX0034 and GEN004840 Complete"



############# SSH restrictions ###############
#
# Uncomment this if you have physical access to the machine.
# This will lock root out from ssh.
# GEN001120 (G500)

# We need to restrict ssh root logins; 
echo "Locking down GEN001120"
perl -npe 's/#PermitRootLogin yes/PermitRootLogin no/' -i /etc/ssh/sshd_config
echo "GEN001120 Complete"

#GEN005540
echo "Locking down GEN005540"
perl -npe 's/^#Banner \/some\/path/Banner \/etc\/issue/g' -i /etc/ssh/sshd_config
echo "GEN005540 Complete"

perl -npe 's/^#ServerKeyBits 768/ServerKeyBits 4096/g' -i /etc/ssh/sshd_config
perl -npe 's/^#MaxAuthTries 6/MaxAuthTries 3/g' -i /etc/ssh/sshd_config


################ Configure a better default firewall ###############
cat << 'EOF' > /etc/sysconfig/iptables-config
#Drop anything we aren't explicitly allowing. All outbound traffic is okay
*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:RH-Firewall-1-INPUT - [0:0]
-A INPUT -j RH-Firewall-1-INPUT
-A FORWARD -j RH-Firewall-1-INPUT
-A RH-Firewall-1-INPUT -i lo -j ACCEPT
-A RH-Firewall-1-INPUT -p icmp --icmp-type echo-reply -j ACCEPT
-A RH-Firewall-1-INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT
-A RH-Firewall-1-INPUT -p icmp --icmp-type time-exceeded -j ACCEPT
# Accept Pings
-A RH-Firewall-1-INPUT -p icmp --icmp-type echo-request -j ACCEPT
# Log anything on eth0 claiming it's from a local or non-routable network
# If you're using one of these local networks, remove it from the list below
-A INPUT -i eth0 -s 172.16.0.0/12 -j LOG --log-prefix "IP DROP SPOOF B: "
-A INPUT -i eth0 -s 192.168.0.0/16 -j LOG --log-prefix "IP DROP SPOOF C: "
-A INPUT -i eth0 -s 240.0.0.0/5 -j LOG --log-prefix "IP DROP SPOOF E: "
-A INPUT -i eth0 -d 127.0.0.0/8 -j LOG --log-prefix "IP DROP LOOPBACK: "
# Accept any established connections
-A RH-Firewall-1-INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Accept ssh traffic. Restrict this to known ips if possible.
-A RH-Firewall-1-INPUT -m state --state NEW -m tcp -p tcp --dport 22 -j ACCEPT
#Log and drop everything else
-A RH-Firewall-1-INPUT -j LOG
-A RH-Firewall-1-INPUT -j DROP
COMMIT
EOF

###### Check to see if we have network access for updates ##########
# For RHEL systems, change the profile name and key
# Documentation for activation keys can be found at 
# http://kbase.redhat.com/faq/docs/DOC-2475
2>/dev/null >/dev/tcp/google.com/80
cat << 'EOF' >> /etc/dnf.conf
deltarpms=1
deltarpms_percentage=90
lock_on_fail=1
EOF
dnf -y update
dnf -y install aide audit vlock i3wm logwatch nmap zsh
################ Beef up the default ruleset for AIDE #################
# Setup AIDE off this baseline
echo "Setting up baseline AIDE configuration ...."
echo "NOTE!!! PLEASE REVIEW THIS, AND EDIT FOR YOUR SPECIFIC CONFIGURATION!"

# Write /etc/aide.conf
echo "Appending default setuid/setgid and 666 f/d to default /etc/aide.conf"
cat << 'EOF' > /etc/aide.conf
# World-Writable files and directories
# Note: There are no ww files in the base install

@@define DBDIR /var/lib/aide
@@define LOGDIR /var/log/aide

# The location of the database to be read.
database=file:@@{DBDIR}/aide.db.gz

# The location of the database to be written.
#database_out=sql:host:port:database:login_name:passwd:table
#database_out=file:aide.db.new
database_out=file:@@{DBDIR}/aide.db.new.gz

# Whether to gzip the output to database
gzip_dbout=yes

# Default.
verbose=5

report_url=file:@@{LOGDIR}/aide.log
report_url=stdout
#report_url=stderr
#NOT IMPLEMENTED report_url=mailto:root@foo.com
#NOT IMPLEMENTED report_url=syslog:LOG_AUTH

# These are the default rules.
#
#p:      permissions
#i:      inode:
#n:      number of links
#u:      user
#g:      group
#s:      size
#b:      block count
#m:      mtime
#a:      atime
#c:      ctime
#S:      check for growing size
#acl:           Access Control Lists
#selinux        SELinux security context
#xattrs:        Extended file attributes
#md5:    md5 checksum
#sha1:   sha1 checksum
#sha256:        sha256 checksum
#sha512:        sha512 checksum
#rmd160: rmd160 checksum
#tiger:  tiger checksum

#haval:  haval checksum (MHASH only)
#gost:   gost checksum (MHASH only)
#crc32:  crc32 checksum (MHASH only)
#whirlpool:     whirlpool checksum (MHASH only)

#FIPSR = p+i+n+u+g+s+m+c+acl+selinux+xattrs+sha256
FIPSR = p+i+n+u+g+s+m+c+acl+selinux+xattrs

#R:             p+i+n+u+g+s+m+c+acl+selinux+xattrs+md5
#L:             p+i+n+u+g+acl+selinux+xattrs
#E:             Empty group
#>:             Growing logfile p+u+g+i+n+S+acl+selinux+xattrs

# You can create custom rules like this.
# With MHASH...
# ALLXTRAHASHES = sha1+rmd160+sha256+sha512+whirlpool+tiger+haval+gost+crc32
ALLXTRAHASHES = sha1+rmd160+sha256+sha512+tiger

# Everything but access time (Ie. all changes)
EVERYTHING = R+ALLXTRAHASHES

# Sane, with multiple hashes
# NORMAL = R+rmd160+sha256+whirlpool
NORMAL = FIPSR+sha512

# For directories, don't bother doing hashes
DIR = p+i+n+u+g+acl+selinux+xattrs

# Access control only
PERMS = p+i+u+g+acl+selinux

# Logfile are special, in that they often change
LOG = >

# Just do sha256 and sha512 hashes
LSPP = FIPSR+sha512

# Some files get updated automatically, so the inode/ctime/mtime change
# but we want to know when the data inside them changes
#DATAONLY =  p+n+u+g+s+acl+selinux+xattrs+sha256
DATAONLY =  p+n+u+g+s+acl+selinux+xattrs+sha512

# Next decide what directories/files you want in the database.

/boot   NORMAL
/bin    NORMAL
/sbin   NORMAL
/lib    NORMAL
/lib64  NORMAL
/opt    NORMAL
/usr    NORMAL
/root   NORMAL

# These are too volatile
!/usr/src
!/usr/tmp

# Check only permissions, inode, user and group for /etc, but
# cover some important files closely.
/etc    PERMS
!/etc/mtab

# Ignore backup files
!/etc/.*~
/etc/exports  NORMAL
/etc/fstab    NORMAL
/etc/passwd   NORMAL
/etc/group    NORMAL
/etc/gshadow  NORMAL
/etc/shadow   NORMAL
/etc/security/opasswd   NORMAL

/etc/hosts.allow   NORMAL
/etc/hosts.deny    NORMAL

/etc/sudoers NORMAL
/etc/skel NORMAL

/etc/logrotate.d NORMAL

/etc/resolv.conf DATAONLY

/etc/nscd.conf NORMAL
/etc/securetty NORMAL

# Shell/X starting files
/etc/profile NORMAL
/etc/bashrc NORMAL
/etc/bash_completion.d/ NORMAL
/etc/login.defs NORMAL
/etc/zprofile NORMAL
/etc/zshrc NORMAL
/etc/zlogin NORMAL
/etc/zlogout NORMAL
/etc/profile.d/ NORMAL
/etc/X11/ NORMAL

# Pkg manager
/etc/yum.conf NORMAL
/etc/yum/ NORMAL
/etc/yum.repos.d/ NORMAL

/var/log   LOG
/var/run/utmp LOG

# This gets new/removes-old filenames daily
!/var/log/sa

# As we are checking it, we've truncated yesterdays size to zero.
!/var/log/aide.log

# LSPP rules...
# AIDE produces an audit record, so this becomes perpetual motion.
# /var/log/audit/ LSPP
/etc/audit/ LSPP
/etc/libaudit.conf LSPP
/usr/sbin/stunnel LSPP
/var/spool/at LSPP
/etc/at.allow LSPP
/etc/at.deny LSPP
/etc/cron.allow LSPP
/etc/cron.deny LSPP
/etc/cron.d/ LSPP
/etc/cron.daily/ LSPP
/etc/cron.hourly/ LSPP
/etc/cron.monthly/ LSPP
/etc/cron.weekly/ LSPP
/etc/crontab LSPP
/var/spool/cron/root LSPP

/etc/login.defs LSPP
/etc/securetty LSPP
/var/log/faillog LSPP
/var/log/lastlog LSPP

/etc/hosts LSPP
/etc/sysconfig LSPP

/etc/inittab LSPP
/etc/grub/ LSPP
/etc/rc.d LSPP

/etc/ld.so.conf LSPP

/etc/localtime LSPP

/etc/sysctl.conf LSPP

/etc/modprobe.conf LSPP

/etc/pam.d LSPP
/etc/security LSPP
/etc/aliases LSPP
/etc/postfix LSPP

/etc/ssh/sshd_config LSPP
/etc/ssh/ssh_config LSPP

/etc/stunnel LSPP

/etc/vsftpd.ftpusers LSPP
/etc/vsftpd LSPP

/etc/issue LSPP
/etc/issue.net LSPP

/etc/cups LSPP

# With AIDE's default verbosity level of 5, these would give lots of
# warnings upon tree traversal. It might change with future version.
#
#=/lost\+found    DIR
#=/home           DIR

# Ditto /var/log/sa reason...
!/var/log/and-httpd

# The root user's dotfiles should not change and need to be watched closely.
/root/\..* NORMAL
EOF

echo "done adding to /etc/aide.conf" 
echo ""
echo "Building a initial AIDE DB..."
/usr/sbin/aide -i
echo "Initial AIDE DB complete"
echo ""
echo "Copying initial AIDE DB to initial baseline AIDE DB..."
cp -p /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
echo "Done copying initital AIDE DB"
echo ""
echo ""
echo "Please review your AIDE configuration, default DB locations,"
echo "cron jobs, etc. to fit your needs"
echo ""
echo "GEN02440 and GEN2380 Complete"

