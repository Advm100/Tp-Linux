# DLC : "L'ultime défi du SysAdmin"
# Étape 1 : Analyse avancée et suppression des traces suspectes
```
[root@localhost etc]# cat passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:65534:65534:Kernel Overflow User:/:/sbin/nologin
tss:x:59:59:Account used for TPM access:/:/usr/sbin/nologin
systemd-coredump:x:999:997:systemd Core Dumper:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
sssd:x:998:996:User for sssd:/:/sbin/nologin
chrony:x:997:995:chrony system user:/var/lib/chrony:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/usr/sbin/nologin
attacker:x:1000:1000::/home/attacker:/bin/bash
```
```
[root@localhost etc]# sudo find /etc /usr/local/bin /var -type f -mtime -7 | grep secure
/etc/lvm/backup/vg_secure
/etc/lvm/archive/vg_secure_00001-960445723.vg
/etc/lvm/archive/vg_secure_00000-1860456324.vg
/etc/lvm/archive/vg_secure_00002-1553545276.vg
/var/log/secure
```
```
[root@localhost etc]# sudo systemctl list-unit-files --state=enabled
UNIT FILE                          STATE   PRESET  
auditd.service                     enabled enabled 
chronyd.service                    enabled enabled 
crond.service                      enabled enabled 
dbus-broker.service                enabled enabled 
firewalld.service                  enabled enabled 
getty@.service                     enabled enabled 
irqbalance.service                 enabled enabled 
kdump.service                      enabled enabled 
lvm2-monitor.service               enabled enabled 
microcode.service                  enabled enabled 
NetworkManager-dispatcher.service  enabled enabled 
NetworkManager-wait-online.service enabled disabled
NetworkManager.service             enabled enabled 
nis-domainname.service             enabled enabled 
rsyslog.service                    enabled enabled 
selinux-autorelabel-mark.service   enabled enabled 
sshd.service                       enabled enabled 
sssd.service                       enabled enabled 
systemd-boot-update.service        enabled enabled 
systemd-network-generator.service  enabled enabled 
dbus.socket                        enabled enabled 
dm-event.socket                    enabled enabled 
lvm2-lvmpolld.socket               enabled enabled 
sssd-kcm.socket                    enabled enabled 
reboot.target                      enabled enabled 
remote-fs.target                   enabled enabled 
dnf-makecache.timer                enabled enabled 
logrotate.timer                    enabled enabled 

28 unit files listed.
```
```
[root@localhost etc]# ls /var/spool/cron/
attacker  root
[root@localhost etc]# sudo crontab -u attacker -r
[root@localhost etc]# ls /var/spool/cron/
root
```
# Étape 2 : Configuration avancée de LVM
```
[root@localhost ~]# sudo lvcreate --snapshot --name secure_data_snapshot --size 500M /dev/vg_secure/secure_data
  Logical Volume "secure_data_snapshot" already exists in volume group "vg_secure"
```
```
[root@localhost ~]# sudo mkdir -p /mnt/secure_data_snapshot
[root@localhost ~]# sudo mount /dev/vg_secure/secure_data_snapshot /mnt/secure_data_snapshot
[root@localhost ~]# ls /mnt/secure_data_snapshot
lost+found  sensitive1.txt  sensitive2.txt
[root@localhost ~]# df -h
Filesystem                                  Size  Used Avail Use% Mounted on
devtmpfs                                    4.0M     0  4.0M   0% /dev
tmpfs                                       3.8G     0  3.8G   0% /dev/shm
tmpfs                                       1.6G  8.6M  1.5G   1% /run
/dev/mapper/rl_vbox-root                    3.4G  1.2G  2.0G  38% /
/dev/sda2                                   974M  190M  718M  21% /boot
/dev/mapper/vg_secure-secure_data           459M   16K  430M   1% /mnt/secure_data
tmpfs                                       769M     0  769M   0% /run/user/0
/dev/mapper/vg_secure-secure_data_snapshot  459M   16K  430M   1% /mnt/secure_data_snapshot
```
```
[root@localhost ~]# sudo rm /mnt/secure_data/sensitive1.txt
[root@localhost ~]# sudo cp /mnt/secure_data_snapshot/sensitive1.txt /mnt/secure_data/
[root@localhost ~]# ls
anaconda-ks.cfg  script.sh  secure_backup.sh
[root@localhost ~]# cd /
[root@localhost /]# cd mnt/secure_data
[root@localhost secure_data]# ls
lost+found  sensitive1.txt  sensitive2.txt
```
# Étape 3 : Renforcement du pare-feu avec des règles dynamiques
```
[root@localhost secure_data]# sudo firewall-cmd --permanent --add-rich-rule="rule family='ipv4' service name='ssh' limit value='2/m' accept"
success
[root@localhost secure_data]# sudo firewall-cmd --reload
success
[root@localhost secure_data]# sudo firewall-cmd --list-all
public (active)
  target: default
  icmp-block-inversion: no
  interfaces: enp0s3 enp0s8
  sources: 
  services: http https ssh
  ports: 2222/tcp
  protocols: 
  forward: yes
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 
        rule family="ipv4" source address="192.168.1.0/24" service name="ssh" accept
        rule family="ipv4" service name="ssh" accept limit value="2/m"
```
### L'accès à SSH à déjà été réstreint dans l'étape 5 du tp1.
```
[root@localhost secure_data]# sudo firewall-cmd --permanent --new-zone=web_zone
success

[root@localhost secure_data]# sudo firewall-cmd --permanent --zone=web_zone --add-service=http
success

[root@localhost secure_data]# sudo firewall-cmd --permanent --zone=web_zone --add-service=https
success

[root@localhost secure_data]# sudo firewall-cmd --permanent --zone=web_zone --set-target=DROP
success


[root@localhost secure_data]# sudo firewall-cmd --permanent --zone=web_zone --change-interface=enp0s8
success

[root@localhost secure_data]# sudo firewall-cmd --reload
success

[root@localhost secure_data]# sudo firewall-cmd --zone=web_zone --list-all
web_zone
  target: DROP
  icmp-block-inversion: no
  interfaces: 
  sources: 
  services: http https
  ports: 
  protocols: 
  forward: no
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 
```
# Étape 4 : Création d'un script de surveillance avancé
```
[root@localhost secure_data]# sudo nano /usr/local/bin/monitor.sh

#!/bin/bash

# Chemin du fichier de log
LOG_FILE="/var/log/monitor.log"

# Fonction pour surveiller les connexions réseau
monitor_connections() {
    echo "=== [$(date)] Connexions actives ===" >> "$LOG_FILE"
    ss -tuna | grep -v "State" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
 while read event; do
        echo "$event" >> "$LOG_FILE"


        echo "Un changement a été détecté : $event" | mailx -s "$SUBJECT" "$EMAIL"
    done &
    INOTIFY_PID=$!  
}

# Fonction pour surveiller les modifications dans /etc
monitor_file_changes() {
    echo "=== [$(date)] Modifications dans /etc ===" >> "$LOG_FILE"
    inotifywait -r -e modify,create,delete,move --format '%T %w%f %e' --timefmt '%Y-%m-%d %H:%M:%S' /etc >> "$LOG_F>
    INOTIFY_PID=$!
}  

# Fonction principale
main() {
    echo "=== Surveillance démarrée à $(date) ===" >> "$LOG_FILE"
    monitor_connections
    monitor_file_changes

    # Surveillance continue (Ctrl+C pour quitter)
    while true; do
        sleep 60  # Intervalle de mise à jour
        monitor_connections
    done
}  

# Nettoyage en cas d'arrêt du script
cleanup() {
    echo "=== Surveillance arrêtée à $(date) ===" >> "$LOG_FILE"
    kill "$INOTIFY_PID" 2>/dev/null
    exit 0
}

# Gestion du signal Ctrl+C
trap cleanup SIGINT SIGTERM

# Exécution
main
```
```
[root@localhost secure_data]# sudo crontab -e
crontab: installing new crontab

*/5 * * * * /usr/local/bin/monitor.sh >> /var/log/monitor_cron.log 2>&1

:wq
```
# Étape 5 : Mise en place d’un IDS (Intrusion Detection System)
```
[root@localhost secure_data]# sudo dnf install aide -y
Last metadata expiration check: 0:00:27 ago on Sun Dec  1 12:21:49 2024.
Package aide-0.16-102.el9.x86_64 is already installed.
Dependencies resolved.
Nothing to do.
Complete!
[root@localhost secure_data]# sudo aide --init
Start timestamp: 2024-12-01 12:22:23 +0100 (AIDE 0.16)
AIDE initialized database at /var/lib/aide/aide.db.new.gz

Number of entries:      33602

---------------------------------------------------
The attributes of the (uncompressed) database(s):
---------------------------------------------------

/var/lib/aide/aide.db.new.gz
  MD5      : 1maOLVAZHTHvqu2Ig2Fqaw==
  SHA1     : z266G1TsjWMdc1IDQQv8vDcoaio=
  RMD160   : hcxRxy9QHzWWNbcbDTV7U60Smm0=
  TIGER    : 6oPDTUgwKjMQVpN4cJBsq3mCoy+BKD4c
  SHA256   : TJ2EuIdZn6N9WNt7JL2jKj6pkmec5Uls
             rmHuDW62V40=
  SHA512   : R/E8tqDFWQSYWFXCs1VZv/oOyaTLfDSm
             PUK2TkaxFgFVs51k47cQ0+x13rEwJl+c
             RBhe76fOmkskScR3CCCLRg==


End timestamp: 2024-12-01 12:22:43 +0100 (run time: 0m 20s)
[root@localhost secure_data]# sudo mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
[root@localhost secure_data]# sudo nano /etc/aide.conf

(ajout "/etc    R")
```
### Modification d'un fichier et verification avec AIDE.
```
[root@localhost secure_data]# sudo nano /etc/hosts
[root@localhost secure_data]# sudo aide --check
Start timestamp: 2024-12-01 12:28:38 +0100 (AIDE 0.16)
AIDE found differences between database and filesystem!!

Summary:
  Total number of entries:      33602
  Added entries:                0
  Removed entries:              0
  Changed entries:              2

---------------------------------------------------
Changed entries:
---------------------------------------------------

f   ...    .C... : /etc/aide.conf
f   ...    .C... : /etc/hosts

---------------------------------------------------
Detailed information about changes:
---------------------------------------------------

File: /etc/aide.conf
  SHA512   : FuQFXyO377TOwHVb/jQVM0dxRYbNdDBL | jfTjrZWLbpUV25EhilOtPPAG0ayW/qLH
             btQhKsF4xN/E5wwLIBIYdTiu5lcFsVbl | BWQ4C5F53m7n5T9RoKcvW5+385IoyvBd
             WcLQL/L0Omjuca1Zh3EHNQ==         | gKb4CgmN8sIODP7mkcdbjw==

File: /etc/hosts
  SHA512   : YobgpcvAMPey0QX1lK4K+5EFySF1xrB/ | 241dd7zXvS4lqw7B4322ZrvXG1pCgK6s
             9FRzTCPNC93+13Y5/lm2inC4x4rydlf2 | ifxGWvTrHSvgh2kjkuBeuZvwTzQDIAK8
             EcvonCf3pHuXj6lEmAjBnw==         | H2mSvEGWI5/9jtETKtbjMA==


---------------------------------------------------
The attributes of the (uncompressed) database(s):
---------------------------------------------------

/var/lib/aide/aide.db.gz
  MD5      : 1maOLVAZHTHvqu2Ig2Fqaw==
  SHA1     : z266G1TsjWMdc1IDQQv8vDcoaio=
  RMD160   : hcxRxy9QHzWWNbcbDTV7U60Smm0=
  TIGER    : 6oPDTUgwKjMQVpN4cJBsq3mCoy+BKD4c
  SHA256   : TJ2EuIdZn6N9WNt7JL2jKj6pkmec5Uls
             rmHuDW62V40=
  SHA512   : R/E8tqDFWQSYWFXCs1VZv/oOyaTLfDSm
             PUK2TkaxFgFVs51k47cQ0+x13rEwJl+c
             RBhe76fOmkskScR3CCCLRg==


End timestamp: 2024-12-01 12:28:44 +0100 (run time: 0m 6s)
```
