data = '''
acpid, adjtimex, ar, arp, arping, ash, awk, basename, blkdiscard,
blockdev, brctl, bunzip2, bzcat, bzip2, cal, cat, chgrp, chmod, chown,
chpasswd, chroot, chvt, clear, cmp, cp, cpio, crond, crontab, cttyhack, cut,
date, dc, dd, deallocvt, depmod, devmem, df, diff, dirname, dmesg,
dnsdomainname, dos2unix, dpkg, dpkg-deb, du, dumpkmap, dumpleases, echo, ed,
egrep, env, expand, expr, factor, fallocate, false, fatattr, fdisk, fgrep,
find, fold, free, freeramdisk, fsfreeze, fstrim, ftpget, ftpput, getopt,
getty, grep, groups, gunzip, gzip, halt, head, hexdump, hostid, hostname,
httpd, hwclock, i2cdetect, i2cdump, i2cget, i2cset, id, ifconfig, ifdown,
ifup, init, insmod, ionice, ip, ipcalc, ipneigh, kill, killall, klogd, last,
less, link, linux32, linux64, linuxrc, ln, loadfont, loadkmap, logger, login,
logname, logread, losetup, ls, lsmod, lsscsi, lzcat, lzma, lzop, md5sum,
mdev, microcom, mkdir, mkdosfs, mke2fs, mkfifo, mknod, mkpasswd, mkswap,
mktemp, modinfo, modprobe, more, mount, mt, mv, nameif, nc, netstat, nl,
nproc, nsenter, nslookup, od, openvt, partprobe, passwd, paste, patch, pidof,
ping, ping6, pivot_root, poweroff, printf, ps, pwd, rdate, readlink,
realpath, reboot, renice, reset, rev, rm, rmdir, rmmod, route, rpm, rpm2cpio,
run-parts, sed, seq, setkeycodes, setpriv, setsid, sh, sha1sum, sha256sum,
sha512sum, shred, shuf, sleep, sort, ssl_client, start-stop-daemon, stat,
static-sh, strings, stty, su, sulogin, svc, swapoff, swapon, switch_root,
sync, sysctl, syslogd, tac, tail, tar, taskset, tee, telnet, telnetd, test,
tftp, time, timeout, top, touch, tr, traceroute, traceroute6, true, truncate,
tty, tunctl, ubirename, udhcpc, udhcpd, uevent, umount, uname, uncompress,
unexpand, uniq, unix2dos, unlink, unlzma, unshare, unxz, unzip, uptime,
usleep, uudecode, uuencode, vconfig, vi, w, watch, watchdog, wc, wget, which,
who, whoami, xargs, xxd, xz, xzcat, yes, zcat
'''

data2 = '''
,bash                ,efibootmgr  ,nano           ,sh.distrib
,btrfs               ,egrep       ,nc             ,sleep
,btrfs-debug-tree    ,false       ,nc.openbsd     ,ss
,btrfs-find-root     ,fgconsole   ,netcat         ,static-sh
,btrfs-image         ,fgrep       ,netstat        ,stty
,btrfs-map-logical   ,findmnt     ,networkctl     ,su
,btrfs-select-super  ,fsck.btrfs  ,nisdomainname  ,sync
,btrfs-zero-log      ,fuser       ,ntfs-3g        ,systemctl
,btrfsck             ,fusermount  ,ntfs-3g.probe  ,systemd
,btrfstune           ,getfacl     ,ntfscat        ,systemd-ask-password
,bunzip2             ,grep        ,ntfscluster    ,systemd-escape
,busybox             ,gunzip      ,ntfscmp        ,systemd-hwdb
,bzcat               ,gzexe       ,ntfsfallocate  ,systemd-inhibit
,bzcmp               ,gzip        ,ntfsfix        ,systemd-machine-id-setup
,bzdiff              ,hostname    ,ntfsinfo       ,systemd-notify
,bzegrep             ,ip          ,ntfsls         ,systemd-sysusers
,bzexe               ,journalctl  ,ntfsmove       ,systemd-tmpfiles
,bzfgrep             ,kbd_mode    ,ntfsrecover    ,systemd-tty-ask-password-agent
,bzgrep              ,kill        ,ntfssecaudit   ,tar
,bzip2               ,kmod        ,ntfstruncate   ,tempfile
,bzip2recover        ,less        ,ntfsusermap    ,touch
,bzless              ,lessecho    ,ntfswipe       ,true
,bzmore              ,lessfile    ,open           ,udevadm
,cat                 ,lesskey     ,openvt         ,ulockmgr_server
,chacl               ,lesspipe    ,pidof          ,umount
,chgrp               ,ln          ,ping           ,uname
,chmod               ,loadkeys    ,ping4          ,uncompress
,chown               ,login       ,ping6          ,unicode_start
,chvt                ,loginctl    ,plymouth       ,vdir
,cp                  ,lowntfs-3g  ,ps             ,wdctl
,cpio                ,ls          ,pwd            ,which
,dash                ,lsblk       ,rbash          ,whiptail
,date                ,lsmod       ,readlink       ,ypdomainname
,dd                  ,mkdir       ,red            ,zcat
,df                  ,mkfs.btrfs  ,rm             ,zcmp
,dir                 ,mknod       ,rmdir          ,zdiff
,dmesg               ,mktemp      ,rnano          ,zegrep
,dnsdomainname       ,more        ,run-parts      ,zfgrep
,domainname          ,mount       ,sed            ,zforce
,dumpkeys            ,mountpoint  ,setfacl        ,zgrep
,echo                ,mt          ,setfont        ,zless
,ed                  ,mt-gnu      ,setupcon       ,zmore
,efibootdump         ,mv          ,sh             ,znew
'''

data = data.strip().replace('\n', '').replace(' ','').split(',')
data2 = data2.strip().replace('\n', '').replace(' ','').split(',')
final = []
for each in data:
  if each in data2:
    final.append(each)
print final
print len(final)