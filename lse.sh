#!/bin/bash
# vim: set ts=2 sw=2 sts=2 et:

# 
lse_version="0.1"

#( Colors
#
# fg
red='\e[31m'
lred='\e[91m'
green='\e[32m'
lgreen='\e[92m'
yellow='\e[33m'
lyellow='\e[93m'
blue='\e[34m'
lblue='\e[94m'
magenta='\e[35m'
lmagenta='\e[95m'
cyan='\e[36m'
lcyan='\e[96m'
grey='\e[90m'
lgrey='\e[37m'
white='\e[97m'
black='\e[30m'
#
# bg
b_red='\e[41m'
b_lred='\e[101m'
b_green='\e[42m'
b_lgreen='\e[102m'
b_yellow='\e[43m'
b_lyellow='\e[103m'
b_blue='\e[44m'
b_lblue='\e[104m'
b_magenta='\e[45m'
b_lmagenta='\e[105m'
b_cyan='\e[46m'
b_lcyan='\e[106m'
b_grey='\e[100m'
b_lgrey='\e[47m'
b_white='\e[107m'
b_black='\e[40m'
#
# special
reset='\e[0;0m'
bold='\e[01m'
italic='\e[03m'
underline='\e[04m'
inverse='\e[07m'
conceil='\e[08m'
crossedout='\e[09m'
bold_off='\e[22m'
italic_off='\e[23m'
underline_off='\e[24m'
inverse_off='\e[27m'
conceil_off='\e[28m'
crossedout_off='\e[29m'
#)

#( Globals
#
# user
lse_user_id="$UID"
[ -z "$lse_user_id" ] && lse_user_id="`id -u`"
lse_user="$USER"
[ -z "$lse_user" ] && lse_user="`id -nu`"
lse_pass=""
lse_home="$HOME"

# system
lse_arch="`uname -m`"
lse_linux="`uname -r`"
lse_hostname="`hostname`"

# lse
lse_passed_tests=""
#)

#( Options
lse_color=true
lse_interactive=true
lse_level=0 #Valid levels 0:default, 1:interesting, 2:all
#)

#( Lib
cecho() {
  if $lse_color; then
    echo -e "$@"
  else
    # If color is disabled we remove it
    echo -e "$@" | sed 's/\x1B\[[0-9;]\+[A-Za-z]//g'
  fi
}
lse_error() {
  cecho "${red}ERROR: ${reset}$*" >&2
}
lse_set_level() {
  case "$1" in
    0|1|2)
      lse_level=$(($1))
      ;;
    *)
      lse_error "Invalid level."
      exit 1
      ;;
  esac
}
lse_help() {
  echo "Use: $0 [options]" 
  echo
  echo " OPTIONS"
  echo "   -c       Disable color"
  echo "   -i       Non interactive mode"
  echo "   -h       This help"
  echo "   -l LEVEL Output verbosity level (0:default, 1:interesting, 2:all)"
}
lse_ask() {
  local question="$1"
  # We use stderr to print the question
  cecho -n "${white}${question}: ${reset}" >&2
  read answer
  case answer in
    y|Y|yes|Yes|ok|Ok|true|True)
      return 0
      ;;
    *)
      echo "$answer"
      return 1
      ;;
  esac
}
lse_request_information() {
  if $lse_interactive; then
  cecho "${grey}---"
    [ -z "$lse_user" ] && lse_user=`lse_ask "Could not find current user name. Current user?"`
    lse_pass=`lse_ask "If you know the current user password, write it here for better results"`
  cecho "${grey}---"
  fi
}
lse_test() {
  # Test id
  local id="$1"
  # Minimum level required for this test to show its output
  local level=$(($2))
  # Name of the current test
  local name="$3"
  # Out put of the test
  local output="$4"

  local l="${lred}!"
  local r="${lgreen}"
  [ $level -eq 1 ] && l="${lyellow}*" && r="${cyan}"
  [ $level -eq 2 ] && l="${lblue}i" && r="${blue}"

  cecho -n "${white}[${l}${white}] $name${grey}"
  for i in $(seq $((${#name}+4)) 74); do
    echo -n "."
  done

  if [ -z "$output" ]; then
    cecho "${grey} nope${reset}"
    return 1
  else
    lse_passed_tests+=" $id"
    cecho "${r} yes!${reset}"
    if [ $lse_level -ge $level ]; then
      cecho "${grey}---$reset"
      echo "$output"
      cecho "${grey}---$reset\n"
    fi
    return 0
  fi
}
lse_test_passed() {
  # Checks if a test passed by ID
  local id="$1"
  for i in $lse_passed_tests; do
    [ "$i" == "$id" ] && return 0
  done
  return 1
}
lse_show_info() {
  echo
  cecho    "${lblue}        User:${reset} $lse_user"
  cecho    "${lblue}     User ID:${reset} $lse_user_id"
  cecho -n "${lblue}    Password:${reset} "
  if [ -z "$lse_pass" ]; then
    cecho "${grey}none${reset}"
  else
    cecho "******"
  fi
  cecho    "${lblue}        Home:${reset} $lse_home"
  cecho    "${lblue}        Path:${reset} $PATH"
  cecho    "${lblue}       umask:${reset} `umask 2>/dev/null`"

  echo
  cecho    "${lblue}    Hostname:${reset} $lse_hostname"
  cecho    "${lblue}       Linux:${reset} $lse_linux"
  cecho    "${lblue}Architecture:${reset} $lse_arch"
  echo
}
lse_header() {
  local title="$*"
  local text="${magenta}"
  for i in $(seq ${#title} 70); do
    text+="="
  done
  text+="(${green} $title ${magenta})====="
  cecho "$text${reset}"
}
#)

#( Main
while getopts "hcil:" option; do
  case "${option}" in
    c) lse_color=false;;
    i) lse_interactive=false;;
    l) lse_set_level "${OPTARG}";;
    h) lse_help; exit 0;;
    *) lse_help; exit 1;;
  esac
done

lse_request_information
lse_show_info
PATH="$PATH:/sbin:/usr/sbin" #fix path just in case
#)

########################################################################( TESTS
#
#  A successful test will receive some output while a failed tests will receive
# an empty string.
#

########################################################################( users 
lse_header "users"

#user groups
lse_user_groups="`groups 2>/dev/null`"
lse_test "usr000" "2" "Current user groups" "$lse_user_groups"

#user in an administrative group
lse_test "usr010" "1" "Is current user in an administrative group?" "`(grep -E '^(adm|admin|root|sudo|wheel)' /etc/group | grep -E \"(:|,)$lse_user\")2>/dev/null`"

#other users in an administrative group
lse_test "usr020" "1" "Are there other users in an administrative groups?" "`(grep -E '^(adm|admin|root|sudo|wheel)' /etc/group | grep -Ev ':$')2>/dev/null`"

#other users with shell
lse_test "usr030" "1" "Other users with shell" "` grep -E 'sh$' /etc/passwd 2>/dev/null`"
  
if [ $lse_level -ge 2 ]; then
  #user env information
  lse_test "usr040" "2" "Environment information" "`(env | grep -v 'LS_COLORS')2>/dev/null`"

  #dump user groups
  lse_test "usr050" "2" "Groups for other users" "`cat /etc/group 2>/dev/null`"

  #dump users
  lse_test "usr060" "2" "Other users" "`cat /etc/passwd 2>/dev/null`"
fi


#########################################################################( sudo
lse_header "sudo"

#variables for sudo checks
lse_sudo=false
lse_sudo_commands=""

#can we sudo without supplying a password
lse_test "sud000" "0" "Can we sudo without a password?" "`echo '' | sudo -S id 2>/dev/null`" && lse_sudo=true

#can we list sudo commands without supplying a password
if ! $lse_sudo; then
  lse_sudo_commands=`echo '' | sudo -S -l 2>/dev/null`
  lse_test "sud010" "0" "Can we list sudo commands without a password?" "$lse_sudo_commands"
fi

if [ "$lse_pass" ]; then
  #can we sudo supplying a password
  if ! $lse_sudo; then
    lse_test "sud020" "0" "Can we sudo with a password?" "$(echo "$lse_pass" | sudo -S id 2>/dev/null)" && lse_sudo=true
  fi

  #can we list sudo commands without supplying a password
  if ! $lse_sudo && [ -z "$lse_sudo_commands" ]; then
    lse_sudo_commands=$(echo "$lse_pass" | sudo -S -l 2>/dev/null)
    lse_test "sud030" "0" "Can we list sudo commands with a password?" "$lse_sudo_commands"
  fi
fi

#check if we can read the sudoers file
lse_test "sud040" "1" "Can we read /etc/sudoers?" "`cat /etc/sudoers 2>/dev/null`"

#check users that sudoed in the past
lse_test "sud050" "1" "Do we know if any other users used sudo?" "`for uh in $(cut -d: -f1,6 /etc/passwd); do [ -f "${uh##*:}/.sudo_as_admin_successful" ] && echo "${uh%%:*}"; done  2>/dev/null`"


##################################################################( file system
lse_header "file system"

#writable files outside user's home
lse_user_writable="`find  / \! -type l -writable -not -path "$HOME/*" -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -not -path "/run/*" 2>/dev/null`"
# Add symlinks owned by the user (so the user can change where they point)
lse_user_writable+="`find  / -type l -user $lse_user -not -path "$HOME/*" -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -not -path "/run/*" 2>/dev/null`"
lse_test "fs000" "1" "Writable files outside users home" "$lse_user_writable"

#get setuid binaries
lse_setuid_binaries="`find / -perm -4000 -type f 2> /dev/null`"
lse_test "fs010" "1" "Binaries with setuid bit" "$lse_setuid_binaries"

if lse_test_passed "fs010"; then
  #uncommon setuid binaries
  lse_test "fs020" "0" "Uncommon setuid binaries" "`echo -e "$lse_setuid_binaries" | grep -Ev '^/(bin|sbin|usr/bin|usr/lib|usr/sbin)' 2>/dev/null`"

  #can we write to any setuid binary
  lse_test "fs030" "0" "Can we write to any setuid binary?" "`for b in $lse_setuid_binaries; do [ -x "$b" ] && [ -w "$b" ] && echo "$b" ;done`"
fi

#get setgid binaries
lse_setgid_binaries="`find / -perm -2000 -type f 2> /dev/null`"
lse_test "fs040" "1" "Binaries with setgid bit" "$lse_setgid_binaries"

if lse_test_passed "fs040"; then
  #uncommon setgid binaries
  lse_test "fs050" "0" "Uncommon setgid binaries" "`echo -e "$lse_setgid_binaries" | grep -Ev '^/(bin|sbin|usr/bin|usr/lib|usr/sbin)' 2>/dev/null`"

  #can we write to any setgid binary
  lse_test "fs060" "0" "Can we write to any setgid binary?" "`for b in $lse_setgid_binaries; do [ -x "$b" ] && [ -w "$b" ] && echo "$b" ;done`"
fi
  
#can we read /root
lse_test "fs070" "1" "Can we read /root?" "`ls -ahl /root/ 2>/dev/null`"

#check /home permissions
lse_test "fs080" "1" "Can we read subdirectories under /home?" "`for h in /home/*; do [ -d "$h" ] && [ "$h" != "$lse_home" ] && ls -la "$h/"; done  2>/dev/null`"

#check for SSH files in home directories
lse_test "fs090" "1" "SSH files in home directories" "`for h in $(cut -d: -f6 /etc/passwd); do find "$h" \( -name "*id_dsa*" -o -name "*id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} 2>/dev/null \; ; done 2>/dev/null`"

if [ $lse_level -ge 2 ]; then
  #files owned by user
  lse_test "fs500" "2" "Files owned by $lse_user" "`find / -user $lse_user -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`"

  #check for SSH files anywhere
  lse_test "fs510" "2" "SSH files anywhere" "`find / \( -name "*id_dsa*" -o -name "*id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} 2>/dev/null \;`"
fi


#######################################################################( system
lse_header "system"

if [ $lse_level -ge 2 ]; then
  #who is logged in
  lse_test "sys000" "2" "Who is logged in" "`w 2>/dev/null`"

  #last logged in users
  lse_test "sys010" "2" "Last logged in users" "`last 2>/dev/null`"
fi

#check if /etc/passwd has the hashes (old system)
lse_test "sys020" "0" "Does the /etc/passwd have hashes?" "`grep -v '^[^:]*:[x]' /etc/passwd 2>/dev/null`"

#check if we can read any shadow file
for s in 'shadow' 'shadow-' 'shadow~' 'master.passwd'; do
  lse_test "sys030" "0" "Can we read /etc/$s file?" "`cat /etc/$s 2>/dev/null`"
done

#check for superuser accounts
lse_test "sys040" "1" "Check for other superuser accounts" "`for u in $(cut -d: -f1 /etc/passwd); do [ $(id -u $u) == 0 ] && echo $u; done 2>/dev/null | grep -v root`"

#can root log in via SSH
lse_test "sys050" "1" "Can user log in via SSH?" "`(grep -E '^[[:space:]]*PermitRootLogin ' /etc/ssh/sshd_config | grep -E '(yes|without-password)')2>/dev/null`"
  
if [ $lse_level -ge 2 ]; then
  #list available shells
  lse_test "sys060" "2" "List available shells" "`cat /etc/shells 2>/dev/null`"

  #system umask
  lse_test "sys070" "2" "System umask in /etc/login.defs" "`grep "^UMASK" /etc/login.defs 2>/dev/null`"

  #system password policies
  lse_test "sys080" "2" "System password policies in /etc/login.defs" "`grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs 2>/dev/null`"
fi

#####################################################################( security
lse_header "security"

#check if selinux is present
lse_test "sel000" "1" "Is SELinux present?" "`sestatus 2>/dev/null`"

#get all binaries with capabilities
lse_cap_bin="`getcap -r / 2> /dev/null`"
lse_test "sel010" "1" "List files with capabilities" "$lse_cap_bin"

#check if we can write an a binary with capabilities
lse_test "sel020" "0" "Can we write to a binary with caps?" "`for b in $(echo -e "$lse_cap_bin" | cut -d' ' -f1); do [ -w "$b" ] && echo "$b"; done 2>/dev/null`"

#check if we have all capabilities in any binary
lse_test "sel030" "0" "Do we have all caps in any binary?" "`(echo -e "$lse_cap_bin" | grep -v 'cap_')2>/dev/null`"

#search /etc/security/capability.conf for users associated capapilies
lse_user_caps=`grep -v '^#\|none\|^$' /etc/security/capability.conf 2>/dev/null`
lse_test "sel040" "1" "Users with associated capabilities" "$lse_user_caps"

if lse_test_passed "sel040"; then
  #does user have capabilities
  show_test "Does current user have capabilities?" "`(echo -e "$lse_user_caps" | grep "$lse_user" )2>/dev/null`"
fi


##############################################################( recurrent tasks 
lse_header "recurrent tasks"

## CRON
#user crontab
lse_test "ret000" "1" "User crontab" "`(crontab -l | grep -Ev '^#')2>/dev/null`"

#cron tasks writable by user
lse_test "ret010" "0" "Cron tasks writable by user" "`echo -e "$lse_user_writable" | grep -E '^/(etc/anacron|etc/cron|var/spool/cron)'`"

#list cron jobs
lse_test "ret020" "1" "Cron jobs" "`grep -ERv '^(#|$)' /etc/crontab /etc/cron.d/ /etc/anacrontab 2>/dev/null`"

#can we read other user crontabs?
lse_test "ret030" "1" "Can we read user crontabs" "`(ls -la /var/spool/cron/crontabs/*)2>/dev/null`"

#can we list other user cron tasks? (you need privileges for this, so if you can something is fishy)
lse_test "ret040" "1" "Can we list other user cron tasks?" "`for u in $(cut -d: -f 1 /etc/passwd); do [ "$u" != "$lse_user" ] && crontab -l -u "$u"; done 2>/dev/null`"

#list cron files
[ $lse_level -ge 2 ] && lse_test "ret400" "2" "Cron files" "`ls -la /etc/cron* 2>/dev/null`"


## Systemd Timers
#user timers
lse_test "ret500" "1" "User systemd timers" "`(systemctl --user list-timers --all | grep -Ev '(^$|timers listed)')2> /dev/null`"

#can we write in any system timer?
lse_test "ret510" "0" "Can we write in any system timer?" "`echo -e "$lse_user_writable" | grep -E '\.timer$'`"

#system timers
[ $lse_level -ge 2 ] && lse_test "ret900" "2" "Systemd timers" "`systemctl list-timers --all 2> /dev/null`"


######################################################################( network
lse_header "network"

#services listening only on localhost
lse_test "net000" "1" "Services listening only on localhost" "`(ss -tunlp || netstat -tunlp)2>/dev/null | grep '127.0.0.1:'`"

#can we execute tcpdump
lse_test "net010" "0" "Can we sniff traffic with tcpdump?" "`(tcpdump -i lo -n 2>&1 & pid=$!;sleep 0.2;kill $pid)2>/dev/null | grep -i 'listening on lo'`"

if [ $lse_level -ge 2 ]; then
  #nic information
  lse_test "net500" "2" "NIC and IP information" "`(ifconfig -a || ip a)2>/dev/null`"

  #routing table
  lse_test "net510" "2" "Routing table" "`(route -n || ip r)2>/dev/null`"

  #arp table
  lse_test "net520" "2" "ARP table" "`(arp -an || ip n)2>/dev/null`"

  #nameservers
  lse_test "net530" "2" "Namerservers" "`grep "nameserver" /etc/resolv.conf 2>/dev/null`"

  #systemd nameservers
  lse_test "net540" "2" "Systemd Nameservers" "`(systemd-resolve --status || systemd-resolve --user --status)2>/dev/null`"

  #listening TCP
  lse_test "net550" "2" "Listening TCP" "`(netstat -tnlp || ss -tnlp)2>/dev/null`"
  
  #listening UDP
  lse_test "net560" "2" "Listening UDP" "`(netstat -unlp || ss -unlp)2>/dev/null`"
fi


#####################################################################( services
lse_header "services"

## System-V
#check write permissions in init.d/* inetd.conf xinetd.conf
lse_test "srv000" "0" "Can we write in service files?" "`echo -e "$lse_user_writable" | grep -E '^/etc/(init/|init\.d/|rc\.d/|rc[0-9S]\.d/|rc\.local|inetd\.conf|xinetd\.conf|xinetd\.d/)'`"

#check write permissions for binaries involved in services
lse_test "srv010" "0" "Can we write in binaries executed by services?" "`
for b in $(grep -ERvh '^#' /etc/inetd.conf /etc/xinetd.conf /etc/xinetd.d/ /etc/init.d/ /etc/rc* 2>/dev/null | tr -s '[[:space:]]' '\n' | grep -E '^/' | grep -Ev '^/(dev|run|sys|proc|tmp)/' | sort | uniq); do
  [ -x "$b" ] && [ -w "$b" ] && echo "$b"
done`"

#init.d files NOT belonging to root
lse_test "srv020" "1" "Files in /etc/init.d/ not belonging to root" "`(find /etc/init.d/ \! -uid 0 -type f | xargs -r ls -la )2>/dev/null`"

#rc.d/init.d files NOT belonging to root!
lse_test "srv030" "1" "Files in /etc/rc.d/init.d not belonging to root" "`(find /etc/rc.d/init.d \! -uid 0 -type f | xargs -r ls -la )2>/dev/null`"

# upstart scripts not belonging to root
lse_test "srv040" "1" "Upstart files not belonging to root" "`(find /etc/init \! -uid 0 -type f | xargs -r ls -la )2>/dev/null`"

#/usr/local/etc/rc.d files NOT belonging to root!
lse_test "srv050" "1" "Files in /usr/local/etc/rc.d not belonging to root" "`(find /usr/local/etc/rc.d \! -uid 0 -type f | xargs -r ls -la )2>/dev/null`"

if [ $lse_level -ge 2 ]; then
  #contents of inetd.conf
  lse_test "srv400" "Contents of /etc/inetd.conf" "`cat /etc/inetd.conf 2>/dev/null`"

  #xinetd info
  lse_test "srv410" "2" "Contents of /etc/xinetd.conf" "`cat /etc/xinetd.conf 2>/dev/null`"

  #check xinetd.d and permissions
  lse_test "srv420" "2" "List /etc/xinetd.d if used" "`grep "/etc/xinetd.d" /etc/xinetd.conf 2>/dev/null; ls -la /etc/xinetd.d 2>/dev/null `"

  #permissions of init.d scripts
  lse_test "srv430" "2" "List /etc/init.d/ permissions" "`ls -la /etc/init.d 2>/dev/null`"

  #rc.d/init.d permissions
  lse_test "srv440" "2" "List /etc/rc.d/init.d permissions" "`ls -la /etc/rc.d/init.d 2>/dev/null`"

  #usr/rc.d permissions
  lse_test "srv450" "2" "List /usr/local/etc/rc.d permissions" "`ls -la /usr/local/etc/rc.d 2>/dev/null`"

  # init permissions
  lse_test "srv460" "2" "List /etc/init/ permissions" "`ls -la /etc/init/ 2>/dev/null`"
fi

## Systemd
#check write permissions in systemd services
lse_test "srv500" "0" "Can we write in systemd service files?" "`echo -e "$lse_user_writable" | grep -E '^/(etc/systemd/|lib/systemd/).+\.service$'`"

#check write permissions for binaries involved in systemd services
lse_test "srv510" "0" "Can we write in binaries executed by systemd services?" "`
for b in $(grep -ERh '^Exec' /etc/systemd/ /lib/systemd/ 2>/dev/null | tr '=' '\n' | tr -s '[[:space:]]' '\n' | grep -E '^/' | grep -Ev '^/(dev|run|sys|proc|tmp)/' | sort | uniq); do
  [ -x "$b" ] && [ -w "$b" ] && echo "$b"
done`"

# systemd files not belonging to root
lse_test "srv520" "1" "Systemd files not belonging to root" "`(find /lib/systemd/ /etc/systemd \! -uid 0 -type f 2>/dev/null | xargs -r ls -la )2>/dev/null`"

if [ $lse_level -ge 2 ]; then
  # systemd permissions
  lse_test "srv900" "2" "Systemd config files permissions" "`ls -lthR /lib/systemd/ /etc/systemd/ 2>/dev/null`"
fi


####################################################################( processes
lse_header "processes"

#lookup process binaries
lse_proc_bin=`(ps -eo comm | sort | uniq | xargs which)2>/dev/null`

#check if we have wire permissions in any process binary
lse_test "ps000" "0" "Can we write in any process binary?" "`for b in $lse_proc_bin; do [ -w "$b" ] && echo $b; done 2>/dev/null`"

if [ $lse_level -ge 2 ]; then
  #running processes
  lse_test "ps500" "2" "Running processes" "`ps auxf 2>/dev/null`"

  #list running process binaries and their permissions
  lse_test "ps510" "2" "Running process binaries and permissions" "`echo -e "$lse_proc_bin" | xargs -n1 ls -l 2>/dev/null`"
fi


#####################################################################( software
lse_header "software"

#checks to see if root/root will get us a connection
lse_test "sw000" "0" "Can we connect to MySQL with root/root credentials?" "`mysqladmin -uroot -proot version 2>/dev/null`"

#checks to see if we can connect as root without password
lse_test "sw010" "0" "Can we connect to MySQL as root without password?" "`mysqladmin -uroot version 2>/dev/null`"

#checks to see if we can connect to postgres templates without password
lse_test "sw020" "0" "Can we connect to PostgreSQL template0 as postgres with no password?" "`psql -U postgres template0 -c 'select version()' 2>/dev/null | grep version`"
lse_test "sw020" "0" "Can we connect to PostgreSQL template1 as postgres with no password?" "`psql -U postgres template1 -c 'select version()' 2>/dev/null | grep version`"
lse_test "sw020" "0" "Can we connect to PostgreSQL template0 as psql with no password?" "`psql -U pgsql template0 -c 'select version()' 2>/dev/null | grep version`"
lse_test "sw020" "0" "Can we connect to PostgreSQL template1 as psql with no password?" "`psql -U pgsql template1 -c 'select version()' 2>/dev/null | grep version`"

#installed apache modules
lse_test "sw030" "1" "Installed apache modules" "`(apache2ctl -M; httpd -M)2>/dev/null`"

#find htpassword files
lse_test "sw040" "0" "Found any .htpasswd files?" "`find / -name "*.htpasswd" -print -exec cat {} \; 2>/dev/null`"

if [ $lse_level -ge 2 ]; then
  #sudo version - check to see if there are any known vulnerabilities with this
  lse_test "sw500" "2" "Sudo version" "`(sudo -V | grep "Sudo version")2>/dev/null`"

  #mysql details - if installed
  lse_test "sw510" "2" "MySQL version" "`mysql --version 2>/dev/null`"

  #postgres details - if installed
  lse_test "sw520" "2" "Postgres version" "`psql -V 2>/dev/null`"

  #apache details - if installed
  lse_test "sw530" "2" "Apache version" "`(apache2 -v; httpd -v )2>/dev/null`"
fi

#
##)
