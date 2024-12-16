# Sécurisation maximale d'un serveur
## Installation et lancement de nginx
```
root@debian:~# sudo apt install nginx
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  nginx-common
Suggested packages:
  fcgiwrap nginx-doc ssl-cert
The following NEW packages will be installed:
  nginx nginx-common
0 upgraded, 2 newly installed, 0 to remove and 0 not upgraded.
Need to get 640 kB of archives.
After this operation, 1696 kB of additional disk space will be used.
Do you want to continue? [Y/n] y
Get:1 http://deb.debian.org/debian bookworm/main amd64 nginx-common all 1.22.1-9 [112 kB]
Get:2 http://deb.debian.org/debian bookworm/main amd64 nginx amd64 1.22.1-9 [527 kB]
Fetched 640 kB in 0s (8223 kB/s)
Preconfiguring packages ...
Selecting previously unselected package nginx-common.
(Reading database ... 37509 files and directories currently installed.)
Preparing to unpack .../nginx-common_1.22.1-9_all.deb ...
Unpacking nginx-common (1.22.1-9) ...
Selecting previously unselected package nginx.
Preparing to unpack .../nginx_1.22.1-9_amd64.deb ...
Unpacking nginx (1.22.1-9) ...
Setting up nginx-common (1.22.1-9) ...
Created symlink /etc/systemd/system/multi-user.target.wants/nginx.service -> /lib/systemd/system/nginx.service.
Setting up nginx (1.22.1-9) ...
Upgrading binary: nginx.
Processing triggers for man-db (2.11.2-2) ...
root@debian:~# sudo systemctl start  nginx
root@debian:~# sudo systemctl start nginx
root@debian:~# sudo systemctl enable nginx
Synchronizing state of nginx.service with SysV service script with /lib/systemd/systemd-sysv-install.
Executing: /lib/systemd/systemd-sysv-install enable nginx
root@debian:~# sudo systemctl status nginx
* nginx.service - A high performance web server and a reverse proxy server
     Loaded: loaded (/lib/systemd/system/nginx.service; enabled; preset: enabled)
     Active: active (running) since Mon 2024-12-16 14:19:51 CET; 2min 21s ago
       Docs: man:nginx(8)
   Main PID: 1450 (nginx)
      Tasks: 2 (limit: 491)
     Memory: 1.7M
        CPU: 16ms
     CGroup: /system.slice/nginx.service
             |-1450 "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"
             `-1451 "nginx: worker process"

Dec 16 14:19:51 debian systemd[1]: Starting nginx.service - A high performance web server and a reverse proxy server...
Dec 16 14:19:51 debian systemd[1]: Started nginx.service - A high performance web server and a reverse proxy server.
root@debian:~# ss -tln | grep :80
LISTEN 0      511          0.0.0.0:80        0.0.0.0:*          
LISTEN 0      511             [::]:80           [::]:* 
```

## Installation de ClamAV pour analyser le serveur et configurer une analyse régulière avec crontab

```
root@debian:~# sudo apt update
sudo apt install clamav clamav-daemon -y
Hit:1 http://deb.debian.org/debian bookworm InRelease
Hit:2 http://security.debian.org/debian-security bookworm-security InRelease
Hit:3 http://deb.debian.org/debian bookworm-updates InRelease
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
All packages are up to date.
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  clamav-base clamav-freshclam clamdscan libclamav11 libmspack0 libncurses6
Suggested packages:
  libclamunrar clamav-docs daemon libclamunrar11
The following NEW packages will be installed:
  clamav clamav-base clamav-daemon clamav-freshclam clamdscan libclamav11 libmspack0 libncurses6
0 upgraded, 8 newly installed, 0 to remove and 0 not upgraded.
Need to get 12.9 MB of archives.

root@debian:~# sudo systemctl stop clamav-freshclam
root@debian:~# sudo freshclam
Mon Dec 16 14:44:41 2024 -> ClamAV update process started at Mon Dec 16 14:44:41 2024
Mon Dec 16 14:44:41 2024 -> daily.cvd database is up-to-date (version: 27489, sigs: 2070428, f-level: 90, builder: raynman)
Mon Dec 16 14:44:41 2024 -> main.cvd database is up-to-date (version: 62, sigs: 6647427, f-level: 90, builder: sigmgr)
Mon Dec 16 14:44:41 2024 -> bytecode.cvd database is up-to-date (version: 335, sigs: 86, f-level: 90, builder: raynman)
root@debian:~# sudo systemctl start clamav-freshclam

root@debian:~# sudo clamscan -r --remove /
^Cading:    33s, ETA:  57s [========>                ]    3.18M/8.72M sigs      


```
```
sudo crontab -e
0 2 * * * clamscan -r --remove / > /var/log/clamav-scan.log
```
## Installation d'un pare-feu

```
root@debian:~# sudo apt update
sudo apt install ufw -y
Hit:1 http://security.debian.org/debian-security bookworm-security InRelease
Hit:2 http://deb.debian.org/debian bookworm InRelease
Hit:3 http://deb.debian.org/debian bookworm-updates InRelease
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
All packages are up to date.
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
The following additional packages will be installed:
  iptables libip6tc2 libnetfilter-conntrack3 libnfnetlink0
Suggested packages:
  firewalld rsyslog
The following NEW packages will be installed:
  iptables libip6tc2 libnetfilter-conntrack3 libnfnetlink0 ufw
0 upgraded, 5 newly installed, 0 to remove and 0 not upgraded.
Need to get 603 kB of archives.
After this operation, 3606 kB of additional disk space will be used.
Get:1 http://deb.debian.org/debian bookworm/main amd64 libip6tc2 amd64 1.8.9-2 [19.4 kB]
Get:2 http://deb.debian.org/debian bookworm/main amd64 libnfnetlink0 amd64 1.0.2-2 [15.1 kB]
Get:3 http://deb.debian.org/debian bookworm/main amd64 libnetfilter-conntrack3 amd64 1.0.9-3 [40.7 kB]
Get:4 http://deb.debian.org/debian bookworm/main amd64 iptables amd64 1.8.9-2 [360 kB]
Get:5 http://deb.debian.org/debian bookworm/main amd64 ufw all 0.36.2-1 [168 kB]
Fetched 603 kB in 0s (7499 kB/s)
Preconfiguring packages ...
Selecting previously unselected package libip6tc2:amd64.
(Reading database ... 37685 files and directories currently installed.)
Preparing to unpack .../libip6tc2_1.8.9-2_amd64.deb ...
Unpacking libip6tc2:amd64 (1.8.9-2) ...
Selecting previously unselected package libnfnetlink0:amd64.
Preparing to unpack .../libnfnetlink0_1.0.2-2_amd64.deb ...
Unpacking libnfnetlink0:amd64 (1.0.2-2) ...
Selecting previously unselected package libnetfilter-conntrack3:amd64.
Preparing to unpack .../libnetfilter-conntrack3_1.0.9-3_amd64.deb ...
Unpacking libnetfilter-conntrack3:amd64 (1.0.9-3) ...
Selecting previously unselected package iptables.
Preparing to unpack .../iptables_1.8.9-2_amd64.deb ...
Unpacking iptables (1.8.9-2) ...
Selecting previously unselected package ufw.
Preparing to unpack .../archives/ufw_0.36.2-1_all.deb ...
Unpacking ufw (0.36.2-1) ...
Setting up libip6tc2:amd64 (1.8.9-2) ...
Setting up libnfnetlink0:amd64 (1.0.2-2) ...
Setting up libnetfilter-conntrack3:amd64 (1.0.9-3) ...
Setting up iptables (1.8.9-2) ...
update-alternatives: using /usr/sbin/iptables-legacy to provide /usr/sbin/iptables (iptables) in auto mode
update-alternatives: using /usr/sbin/ip6tables-legacy to provide /usr/sbin/ip6tables (ip6tables) in auto mode
update-alternatives: using /usr/sbin/iptables-nft to provide /usr/sbin/iptables (iptables) in auto mode
update-alternatives: using /usr/sbin/ip6tables-nft to provide /usr/sbin/ip6tables (ip6tables) in auto mode
update-alternatives: using /usr/sbin/arptables-nft to provide /usr/sbin/arptables (arptables) in auto mode
update-alternatives: using /usr/sbin/ebtables-nft to provide /usr/sbin/ebtables (ebtables) in auto mode
Setting up ufw (0.36.2-1) ...

Creating config file /etc/ufw/before.rules with new version

Creating config file /etc/ufw/before6.rules with new version

Creating config file /etc/ufw/after.rules with new version

Creating config file /etc/ufw/after6.rules with new version
Created symlink /etc/systemd/system/multi-user.target.wants/ufw.service -> /lib/systemd/system/ufw.service.
Processing triggers for libc-bin (2.36-9+deb12u9) ...
Processing triggers for man-db (2.11.2-2) ...
root@debian:~# ^C
root@debian:~# sudo ufw allow ssh
Rules updated
Rules updated (v6)
root@debian:~# sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
Rules updated
Rules updated (v6)
Rules updated
Rules updated (v6)
root@debian:~# sudo ufw default deny incoming
sudo ufw default allow outgoing
Default incoming policy changed to 'deny'
(be sure to update your rules accordingly)
Default outgoing policy changed to 'allow'
(be sure to update your rules accordingly)
root@debian:~# sudo ufw enable
Command may disrupt existing ssh connections. Proceed with operation (y|n)? y
Firewall is active and enabled on system startup
root@debian:~# sudo ufw status verbose
Status: active
Logging: on (low)
Default: deny (incoming), allow (outgoing), disabled (routed)
New profiles: skip

To                         Action      From
--                         ------      ----
22/tcp                     ALLOW IN    Anywhere                  
80/tcp                     ALLOW IN    Anywhere                  
443/tcp                    ALLOW IN    Anywhere                  
22/tcp (v6)                ALLOW IN    Anywhere (v6)             
80/tcp (v6)                ALLOW IN    Anywhere (v6)             
443/tcp (v6)               ALLOW IN    Anywhere (v6)   
```
## Désactiver les services inutiles 
Plus il y a de services disponibles sur un serveur plus il y a de faille, pour pallier à ça on peut désactiver les services inutiles.

```
sudo systemctl list-units --type=service
sudo systemctl disable nom_du_service
```
## Configuration fail2ban (anti force brute)
```
sudo apt install fail2ban -y
sudo systemctl enable fail2ban
sudo systemctl start fail2ban
```
## Configurer un certificat SSL avec HTTPS (convertion des connexions HTTP en HTTPS )


## Mettre en place un IDS (Intrusion Detection System(analyse trafic réseau))
```
sudo apt install aide -y
sudo aideinit
sudo cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

sudo aide --check
```
