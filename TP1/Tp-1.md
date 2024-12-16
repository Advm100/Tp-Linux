# TP Avancé : "Mission Ultime : Sauvegarde et Sécurisation"
# Étape 1 : Analyse et nettoyage du serveur
```
[root@localhost ~]# cat /etc/passwd
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
sshd:x:74:74:Privilege-separated SSH:/usr/share/empty.sshd:/usr/sbin/   nologin
attacker:x:1000:1000::/home/attacker:/bin/bash

[root@localhost ~]# sudo crontab -u attacker -l
*/10 * * * * /tmp/.hidden_script
```
```
[root@localhost tmp]# cd /tmp/
[root@localhost tmp]# ls -a
.             .hidden_script
..            malicious.sh
.ICE-unix     systemd-private-0b4e3fb992974528ab8cdd656f9c142c-chronyd.service-1QiMaX
.X11-unix     systemd-private-0b4e3fb992974528ab8cdd656f9c142c-dbus-broker.service-1AXSFa
.XIM-unix     systemd-private-0b4e3fb992974528ab8cdd656f9c142c-irqbalance.service-gtBkGR
.font-unix    systemd-private-0b4e3fb992974528ab8cdd656f9c142c-kdump.service-J1aFAy
.hidden_file  systemd-private-0b4e3fb992974528ab8cdd656f9c142c-systemd-logind.service-yJSVuR
[root@localhost tmp]# rm .hidden_script malicious.sh .hidden_file
rm: remove regular file '.hidden_script'? y
rm: remove regular file 'malicious.sh'? y
rm: remove regular file '.hidden_file'? y
[root@localhost tmp]# ls -a
.           systemd-private-0b4e3fb992974528ab8cdd656f9c142c-chronyd.service-1QiMaX
..          systemd-private-0b4e3fb992974528ab8cdd656f9c142c-dbus-broker.service-1AXSFa
.ICE-unix   systemd-private-0b4e3fb992974528ab8cdd656f9c142c-irqbalance.service-gtBkGR
.X11-unix   systemd-private-0b4e3fb992974528ab8cdd656f9c142c-kdump.service-J1aFAy
.XIM-unix   systemd-private-0b4e3fb992974528ab8cdd656f9c142c-systemd-logind.service-yJSVuR
.font-unix
```
```
[root@localhost tmp]# sudo ss -tunap
Netid      State       Recv-Q      Send-Q                   Local Address:Port              Peer Address:Port       Process                                                                                                             
udp        ESTAB       0           0                192.168.56.101%enp0s8:68              192.168.56.100:67          users:(("NetworkManager",pid=874,fd=33))                                                                           
udp        ESTAB       0           0                     10.0.2.15%enp0s3:68                    10.0.2.2:67          users:(("NetworkManager",pid=874,fd=28))                                                                           
udp        UNCONN      0           0                            127.0.0.1:323                    0.0.0.0:*           users:(("chronyd",pid=870,fd=5))                                                                                   
udp        UNCONN      0           0                                [::1]:323                       [::]:*           users:(("chronyd",pid=870,fd=6))                                                                                   
tcp        LISTEN      0           128                            0.0.0.0:22                     0.0.0.0:*           users:(("sshd",pid=902,fd=3))                                                                                      
tcp        ESTAB       0           0                       192.168.56.101:22                192.168.56.1:39902       users:(("sshd",pid=1754,fd=4),("sshd",pid=1750,fd=4))                                                              
tcp        LISTEN      0           128                               [::]:22                        [::]:*           users:(("sshd",pid=902,fd=4))    
```
# Étape 2 : Configuration avancée de LVM
```
[root@localhost tmp]# sudo lvcreate --snapshot --name mylv_snapshot --size 500M /dev/vg_secure/secure_data 
  Logical volume "mylv_snapshot" created.
```
```
[root@localhost tmp]# sudo mkdir /mnt/mylv_snapshot
[root@localhost tmp]# sudo mount /dev/vg_secure/mylv_snapshot /mnt/mylv_snapshot
[root@localhost tmp]# ls /mnt/mylv_snapshot
lost+found  sensitive1.txt  sensitive2.txt
[root@localhost tmp]# sudo cp /mnt/mylv_snapshot/sensitive1.txt /mnt/secure_data/
[root@localhost tmp]# sudo cp /mnt/mylv_snapshot/sensitive1.txt /mnt/secure_data/
[root@localhost tmp]# ls /mnt/secure_data
lost+found  sensitive1.txt  sensitive2.txt
```
```
[root@localhost tmp]# sudo lvchange -an /dev/vg_secure/secure_data 
  Logical volume vg_secure/secure_data contains a filesystem in use.
[root@localhost tmp]# mount | grep secure_data
/dev/mapper/vg_secure-secure_data on /mnt/secure_data type ext4 (rw,relatime,seclabel)
[root@localhost tmp]# sudo umount /mnt/secure_data
[root@localhost tmp]# sudo lvchange -an /dev/vg_secure/secure_data
  Logical volume vg_secure/mylv_snapshot contains a filesystem in use.
  LV vg_secure/secure_data has open 1 snapshot(s), not deactivating.
[root@localhost tmp]# ^C
[root@localhost tmp]# sudo lvextend -L +3M /dev/vg_secure/secure_data
  Rounding size to boundary between physical extents: 4.00 MiB.
  Snapshot origin volumes can be resized only while inactive: try lvchange -an.
```
# Étape 3 : Automatisation avec un script de sauvegarde
```
#!/bin/bash

# Variables
SOURCE_DIR="/mnt/secure_data"
BACKUP_DIR="/backup"
DATE=$(date +"%Y%m%d")
BACKUP_FILE="${BACKUP_DIR}/secure_data_${DATE}.tar.gz"
RETENTION_DAYS=7  # Nombre de jours à conserver les sauvegardes

# Exclusion des fichiers .tmp, .log et fichiers cachés
EXCLUDE_PATTERN="--exclude=*.tmp --exclude=*.log --exclude=.*"

# Vérification que le répertoire source existe
if [ ! -d "$SOURCE_DIR" ]; then
    echo "Erreur : Le répertoire source ${SOURCE_DIR} n'existe pas."
    exit 1
fi

# Création du répertoire de sauvegarde s'il n'existe pas
if [ ! -d "$BACKUP_DIR" ]; then
    echo "Création du répertoire de sauvegarde ${BACKUP_DIR}..."
    mkdir -p "$BACKUP_DIR"
fi

# Création de l'archive
echo "Création de la sauvegarde dans ${BACKUP_FILE}..."
tar czf "$BACKUP_FILE" $EXCLUDE_PATTERN -C "$SOURCE_DIR" .

# Vérification du succès
if [ $? -eq 0 ]; then
    echo "Sauvegarde réussie : ${BACKUP_FILE}"
else
    echo "Erreur lors de la création de la sauvegarde."
    exit 2
fi

# Rotation des sauvegardes
rotate_backups() {
    echo "Rotation des sauvegardes : suppression des fichiers de plus de ${RETENTION_DAYS} jours..."
    find "$BACKUP_DIR" -type f -name "secure_data_*.tar.gz" -mtime +${RETENTION_DAYS} -exec rm -f {} \;
    echo "Rotation terminée."
}

rotate_backups
```
```
[root@localhost ~]# /root/secure_backup.sh
Création de la sauvegarde dans /backup/secure_data_20241130.tar.gz...
Sauvegarde réussie : /backup/secure_data_20241130.tar.gz
Rotation des sauvegardes : suppression des fichiers de plus de 7 jours...
Rotation terminée.
```
```
[root@localhost ~]# sudo crontab -e

0 3 * * * /root/secure_backup.sh

crontab: installing new crontab
```
# Étape 4 : Surveillance avancée avec auditd
```
[root@localhost ~]#  sudo auditctl -a always,exit -F arch=b64 -S open,openat,creat,unlink,rename -F dir=/etc -F perm=wa -k etc_changes
[root@localhost ~]# sudo cat /etc/audit/rules.d/audit.rules
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## This determine how long to wait in burst of events
--backlog_wait_time 60000

## Set failure mode to syslog
-f 1
```
```
[root@localhost ~]# sudo touch /etc/test_audit
[root@localhost ~]# echo "Test auditd" | sudo tee -a /etc/test_audit
Test auditd
[root@localhost ~]# sudo rm /etc/test_audit
[root@localhost ~]# sudo ausearch -k etc_changes | grep etc_changes
type=CONFIG_CHANGE msg=audit(1732469431.730:216): auid=0 ses=3 subj=unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023 op=add_rule key="etc_changes" list=4 res=1
type=SYSCALL msg=audit(1732469448.887:224): arch=c000003e syscall=257 success=yes exit=13 a0=ffffff9c a1=7f8c523a45a0 a2=80241 a3=1b6 items=2 ppid=1 pid=796 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="firewalld" exe="/usr/bin/python3.9" subj=system_u:system_r:firewalld_t:s0 key="etc_changes"
type=SYSCALL msg=audit(1732469448.892:225): arch=c000003e syscall=188 success=yes exit=0 a0=7f8c523a45a0 a1=7f8c5245dbd0 a2=7f8c523a4550 a3=28 items=1 ppid=1 pid=796 auid=4294967295 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=(none) ses=4294967295 comm="firewalld" exe="/usr/bin/python3.9" subj=system_u:system_r:firewalld_t:s0 key="etc_changes"
```
```
[root@localhost ~]# sudo ausearch -k etc_changes > /var/log/audit_etc.log

```
# Étape 5 : Sécurisation avec Firewalld
```
[root@localhost ~]# sudo firewall-cmd --permanent --add-service=ssh
Warning: ALREADY_ENABLED: ssh
success
[root@localhost ~]# sudo firewall-cmd --permanent --add-service=http
success
[root@localhost ~]# sudo firewall-cmd --permanent --add-service=https
Warning: ALREADY_ENABLED: https
success
[root@localhost ~]# sudo firewall-cmd --list-all
public (active)
  target: default
  icmp-block-inversion: no
  interfaces: enp0s3 enp0s8
  sources: 
  services: cockpit dhcpv6-client https ssh
  ports: 2222/tcp
  protocols: 
  forward: yes
  masquerade: no
  forward-ports: 
  source-ports: 
  icmp-blocks: 
  rich rules: 
[root@localhost ~]# sudo firewall-cmd --permanent --remove-service=cockpit
success
[root@localhost ~]#  sudo firewall-cmd --permanent --remove-service=dhcpv6-client
success

```
```
[root@localhost ~]# sudo firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='192.168.1.0/24' service name='ssh' accept"
success
[root@localhost ~]# sudo firewall-cmd --reload
success
[root@localhost ~]# sudo firewall-cmd --list-rich-rules
rule family="ipv4" source address="192.168.1.0/24" service name="ssh" accept
```
```

