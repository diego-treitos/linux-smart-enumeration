#!/bin/bash
# vim: set ts=2 sw=2 sts=2 et:

# Author: Diego Blanco <diego.blanco@treitos.com>
# GitHub: https://github.com/diego-treitos/linux-smart-enumeration
# 
lse_version="1.7"

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
[ -z "$lse_home" ] && lse_home="`(grep -E "^$lse_user:" /etc/passwd | cut -d: -f6)2>/dev/null`"

# system
lse_arch="`uname -m`"
lse_linux="`uname -r`"
lse_hostname="`hostname`"
lse_distro=`command -v lsb_release >/dev/null 2>&1 && lsb_release -d | sed 's/Description:\s*//' 2>/dev/null`
[ -z "$lse_distro" ] && lse_distro="`(source /etc/os-release && echo "$PRETTY_NAME")2>/dev/null`"

# lse
lse_passed_tests=""
lse_executed_tests=""
lse_DEBUG=false

# internal data
lse_common_setuid=(
  '/bin/fusermount'
  '/bin/mount'
  '/bin/ntfs-3g'
  '/bin/ping'
  '/bin/ping6'
  '/bin/su'
  '/bin/umount'
  '/lib64/dbus-1/dbus-daemon-launch-helper'
  '/sbin/mount.ecryptfs_private'
  '/sbin/mount.nfs'
  '/sbin/pam_timestamp_check'
  '/sbin/pccardctl'
  '/sbin/unix2_chkpwd'
  '/sbin/unix_chkpwd'
  '/usr/bin/Xorg'
  '/usr/bin/arping'
  '/usr/bin/at'
  '/usr/bin/beep'
  '/usr/bin/chage'
  '/usr/bin/chfn'
  '/usr/bin/chsh'
  '/usr/bin/crontab'
  '/usr/bin/expiry'
  '/usr/bin/firejail'
  '/usr/bin/fusermount'
  '/usr/bin/fusermount-glusterfs'
  '/usr/bin/gpasswd'
  '/usr/bin/kismet_capture'
  '/usr/bin/mount'
  '/usr/bin/mtr'
  '/usr/bin/newgidmap'
  '/usr/bin/newgrp'
  '/usr/bin/newuidmap'
  '/usr/bin/passwd'
  '/usr/bin/pkexec'
  '/usr/bin/procmail'
  '/usr/bin/staprun'
  '/usr/bin/su'
  '/usr/bin/sudo'
  '/usr/bin/sudoedit'
  '/usr/bin/traceroute6.iputils'
  '/usr/bin/umount'
  '/usr/bin/weston-launch'
  '/usr/lib/chromium-browser/chrome-sandbox'
  '/usr/lib/dbus-1.0/dbus-daemon-launch-helper'
  '/usr/lib/dbus-1/dbus-daemon-launch-helper'
  '/usr/lib/eject/dmcrypt-get-device'
  '/usr/lib/openssh/ssh-keysign'
  '/usr/lib/policykit-1/polkit-agent-helper-1'
  '/usr/lib/polkit-1/polkit-agent-helper-1'
  '/usr/lib/pt_chown'
  '/usr/lib/snapd/snap-confine'
  '/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper'
  '/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic'
  '/usr/lib/xorg/Xorg.wrap'
  '/usr/libexec/Xorg.wrap'
  '/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache'
  '/usr/libexec/dbus-1/dbus-daemon-launch-helper'
  '/usr/libexec/gstreamer-1.0/gst-ptp-helper'
  '/usr/libexec/openssh/ssh-keysign'
  '/usr/libexec/polkit-1/polkit-agent-helper-1'
  '/usr/libexec/pt_chown'
  '/usr/libexec/qemu-bridge-helper'
  '/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper'
  '/usr/sbin/exim4'
  '/usr/sbin/grub2-set-bootflag'
  '/usr/sbin/mount.nfs'
  '/usr/sbin/mtr-packet'
  '/usr/sbin/pam_timestamp_check'
  '/usr/sbin/pppd'
  '/usr/sbin/pppoe-wrapper'
  '/usr/sbin/suexec'
  '/usr/sbin/unix_chkpwd'
  '/usr/sbin/userhelper'
  '/usr/sbin/usernetctl'
  '/usr/sbin/uuidd'
)
#regex rules for common setuid
lse_common_setuid+=(
  '/snap/core/.*'
  '/var/tmp/mkinitramfs.*'
)
#)

#( Options
lse_color=true
lse_interactive=true
lse_level=0 #Valid levels 0:default, 1:interesting, 2:all
lse_selection="" #Selected tests to run. Empty means all.
#)

#( Lib
cecho() {
  if $lse_color; then
    printf "$@"
  else
    # If color is disabled we remove it
    printf "$@" | sed 's/\x1B\[[0-9;]\+[A-Za-z]//g'
  fi
}
lse_error() {
  cecho "${red}ERROR: ${reset}$*\n" >&2
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
  echo "   -c           Disable color"
  echo "   -i           Non interactive mode"
  echo "   -h           This help"
  echo "   -l LEVEL     Output verbosity level"
  echo "                  0: Show highly important results. (default)"
  echo "                  1: Show interesting results."
  echo "                  2: Show all gathered information."
  echo "   -s SELECTION Comma separated list of sections or tests to run. Available"
  echo "                sections:"
  echo "                  usr: User related tests."
  echo "                  sud: Sudo related tests."
  echo "                  fst: File system related tests."
  echo "                  sys: System related tests."
  echo "                  sec: Security measures related tests."
  echo "                  ret: Recurren tasks (cron, timers) related tests."
  echo "                  net: Network related tests."
  echo "                  srv: Services related tests."
  echo "                  pro: Processes related tests."
  echo "                  sof: Software related tests."
  echo "                  ctn: Container (docker, lxc) related tests."
  echo "                Specific tests can be used with their IDs (i.e.: usr020,sud)"
}
lse_ask() {
  local question="$1"
  # We use stderr to print the question
  cecho "${white}${question}: ${reset}" >&2
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
  cecho "${grey}---\n"
    [ -z "$lse_user" ] && lse_user=`lse_ask "Could not find current user name. Current user?"`
    lse_pass=`lse_ask "If you know the current user password, write it here for better results"`
  cecho "${grey}---\n"
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
lse_test() {
  # Test id
  local id="$1"
  # Minimum level required for this test to show its output
  local level=$(($2))
  # Name of the current test
  local name="$3"
  # Output of the test
  local cmd="$4"
  # Dependencies
  local deps="$5"
  # Variable name where to store the output
  local var="$6"

  # Define colors
  local l="${lred}!"
  local r="${lgreen}"
  [ $level -eq 1 ] && l="${lyellow}*" && r="${cyan}"
  [ $level -eq 2 ] && l="${lblue}i" && r="${blue}"

  # Filter selected tests
  if [ "$lse_selection" ]; then
    local sel_match=false
    for s in $lse_selection; do
      if [ "$s" == "$id" ] || [ "$s" == "${id:0:3}" ]; then
        sel_match=true
      fi
    done
    $sel_match || return 0
  fi

  # DEBUG messages
  $lse_DEBUG && cecho "${lmagenta}DEBUG: ${lgreen}Executing: ${reset}$cmd\n"

  # Print name and line
  cecho "${white}[${l}${white}] ${grey}${id}${white} $name${grey}"
  for i in $(seq $((${#name}+4)) 67); do
    echo -n "."
  done

  # Check dependencies
  local non_met_deps=""
  for d in $deps; do
    lse_test_passed "$d" || non_met_deps+="$d"
  done
  if [ "$non_met_deps" ]; then
    cecho " ${grey}skip\n"
    # In "selection mode" we print the missed dependencies
    if [ "$lse_selection" ]; then
      cecho "${red}---\n"
      cecho "Dependencies not met:$reset $non_met_deps\n"
      cecho "${red}---$reset\n"
    fi
    return 1
  fi 

  # If level is 2 we do not execute level 2 tests unless their output needs
  # to be assigned to a variable
  if [ $level -ge 2 ] && [ $lse_level -lt 2 ] && [ -z "$var" ]; then
    cecho " ${grey}skip\n"
    return 1
  else
    if $lse_DEBUG; then
      output="`eval "$cmd" 2>&1`"
    else
      # Execute comand
      output="`eval "$cmd" 2>/dev/null`"
    # Assign variable if available
    fi
    [ "$var" ] && eval "$var='$output'"
    # Mark test as executed
    lse_executed_tests+=" $id"
  fi

  if [ -z "$output" ]; then
    cecho "${grey} nope${reset}\n"
    return 1
  else
    lse_passed_tests+=" $id"
    cecho "${r} yes!${reset}\n"
    if [ $lse_level -ge $level ]; then
      cecho "${grey}---$reset\n"
      echo "$output"
      cecho "${grey}---$reset\n"
    fi
    return 0
  fi
}
lse_show_info() {
  echo
  cecho "${lblue}        User:${reset} $lse_user\n"
  cecho "${lblue}     User ID:${reset} $lse_user_id\n"
  cecho "${lblue}    Password:${reset} "
  if [ -z "$lse_pass" ]; then
    cecho "${grey}none${reset}\n"
  else
    cecho "******\n"
  fi
  cecho "${lblue}        Home:${reset} $lse_home\n"
  cecho "${lblue}        Path:${reset} $PATH\n"
  cecho "${lblue}       umask:${reset} `umask 2>/dev/null`\n"

  echo
  cecho "${lblue}    Hostname:${reset} $lse_hostname\n"
  cecho "${lblue}       Linux:${reset} $lse_linux\n"
	if [ "$lse_distro" ]; then
  cecho "${lblue}Distribution:${reset} $lse_distro\n"
	fi
  cecho "${lblue}Architecture:${reset} $lse_arch\n"
  echo
}
lse_header() {
  local id="$1"
  shift
  local title="$*"
  local text="${magenta}"

  # Filter selected tests
  if [ "$lse_selection" ]; then
    local sel_match=false
    for s in $lse_selection; do
      if [ "${s:0:3}" == "$id" ]; then
        sel_match=true
        break
      fi
    done
    $sel_match || return 0
  fi

  for i in $(seq ${#title} 70); do
    text+="="
  done
  text+="(${green} $title ${magenta})====="
  cecho "$text${reset}\n"
}
lse_exit() {
  local ec=1
  local text="\n${magenta}=================================="
  [ "$1" ] && ec=$1
  text+="(${green} FINISHED ${magenta})=================================="
  cecho "$text${reset}\n"
  exit $ec
}
#)

########################################################################( TESTS
#
#  A successful test will receive some output while a failed tests will receive
# an empty string.
#
########################################################################( users 
lse_run_tests_users() {
  lse_header "usr" "users"

  #user groups
  lse_test "usr000" "2" \
    "Current user groups" \
    'groups' \
    "" \
    "lse_user_groups"

  #user in an administrative group
  lse_test "usr010" "1" \
    "Is current user in an administrative group?" \
    'grep -E "^(adm|admin|root|sudo|wheel)" /etc/group | grep -E "(:|,)$lse_user"'

  #other users in an administrative group
  lse_test "usr020" "1" \
    "Are there other users in an administrative groups?" \
    'grep -E "^(adm|admin|root|sudo|wheel)" /etc/group | grep -Ev ":$"'

  #other users with shell
  lse_test "usr030" "1" \
    "Other users with shell" \
    'grep -E "sh$" /etc/passwd'
    
  #user env information
  lse_test "usr040" "2" \
    "Environment information" \
    'env | grep -v "LS_COLORS"'

  #dump user groups
  lse_test "usr050" "2" \
    "Groups for other users" \
    'cat /etc/group'

  #dump users
  lse_test "usr060" "2" \
    "Other users" \
    'cat /etc/passwd'
}


#########################################################################( sudo
lse_run_tests_sudo() {
  lse_header "sud" "sudo"

  #variables for sudo checks
  lse_sudo=false
  lse_sudo_commands=""

  #can we sudo without supplying a password
  lse_test "sud000" "0" \
    "Can we sudo without a password?" \
    'echo "" | sudo -S id' && lse_sudo=true

  #can we list sudo commands without supplying a password
  $lse_sudo || \
    lse_test "sud010" "0" \
    "Can we list sudo commands without a password?" \
    'echo "" | sudo -S -l' \
    "" \
    "lse_sudo_commands"

  if [ "$lse_pass" ]; then
    #can we sudo supplying a password
    $lse_sudo || \
      lse_test "sud020" "0" \
      "Can we sudo with a password?" \
      'echo "$lse_pass" | sudo -S id' && lse_sudo=true

    #can we list sudo commands without supplying a password
    if ! $lse_sudo && [ -z "$lse_sudo_commands" ]; then
      lse_test "sud030" "0" \
        "Can we list sudo commands with a password?" \
        'echo "$lse_pass" | sudo -S -l' \
        "" \
        "lse_sudo_commands"
    fi
  fi

  #check if we can read the sudoers file
  lse_test "sud040" "1" \
    "Can we read /etc/sudoers?" \
    'cat /etc/sudoers'

  #check users that sudoed in the past
  lse_test "sud050" "1" \
    "Do we know if any other users used sudo?" \
    'for uh in $(cut -d: -f1,6 /etc/passwd); do [ -f "${uh##*:}/.sudo_as_admin_successful" ] && echo "${uh%%:*}"; done'
}


##################################################################( file system
lse_run_tests_filesystem() {
  lse_header "fst" "file system"

  #writable files outside user's home. NOTE: Does not check if user can write in symlink destination (performance reasons: -L implies -noleaf)
  lse_test "fst000" "1" \
    "Writable files outside user's home" \
    'find  / \! -type l -writable -not -path "$HOME/*" -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -not -path "/run/*"; 
    # Add symlinks owned by the user (so the user can change where they point)
    find  / -type l -user $lse_user -not -path "$HOME/*" -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -not -path "/run/*"' \
    "" \
    "lse_user_writable"

  #get setuid binaries
  lse_test "fst010" "1" \
    "Binaries with setuid bit" \
    'find / -perm -4000 -type f' \
    "" \
    "lse_setuid_binaries"

  #uncommon setuid binaries
  lse_test "fst020" "0" \
    "Uncommon setuid binaries" \
    'local setuidbin="$lse_setuid_binaries"; for cs in "${lse_common_setuid[@]}"; do setuidbin=`echo -e "$setuidbin" | grep -Ev "$cs"`;done ; echo -e "$setuidbin"' \
    "fst010"

  #can we write to any setuid binary
  lse_test "fst030" "0" \
    "Can we write to any setuid binary?" \
    'for b in $lse_setuid_binaries; do [ -x "$b" ] && [ -w "$b" ] && echo "$b" ;done' \
    "fst010"

  #get setgid binaries
  lse_test "fst040" "1" \
    "Binaries with setgid bit" \
    'find / -perm -2000 -type f' \
    "lse_setgid_binaries"

  #uncommon setgid binaries
  lse_test "fst050" "0" \
    "Uncommon setgid binaries" \
    'echo -e "$lse_setgid_binaries" | grep -Ev "^/(bin|sbin|usr/bin|usr/lib|usr/sbin)"' \
    "fst040"

  #can we write to any setgid binary
  lse_test "fst060" "0" \
    "Can we write to any setgid binary?" \
    'for b in $lse_setgid_binaries; do [ -x "$b" ] && [ -w "$b" ] && echo "$b" ;done' \
    "fst040"
    
  #can we read /root
  lse_test "fst070" "1" \
    "Can we read /root?" \
    'ls -ahl /root/'

  #check /home permissions
  lse_test "fst080" "1" \
    "Can we read subdirectories under /home?" \
    'for h in /home/*; do [ -d "$h" ] && [ "$h" != "$lse_home" ] && ls -la "$h/"; done'

  #check for SSH files in home directories
  lse_test "fst090" "1" \
    "SSH files in home directories" \
    'for h in $(cut -d: -f6 /etc/passwd); do find "$h" \( -name "*id_dsa*" -o -name "*id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} \; ; done'

  #check useful binaries
  lse_test "fst100" "1" \
    "Useful binaries" \
    'which curl; which dig; which gcc; which nc.openbsd; which nc; which netcat; which nmap; which socat; which wget'

  #check for interesting files in home directories
  lse_test "fst110" "1" \
    "Other interesting files in home directories" \
    'for h in $(cut -d: -f6 /etc/passwd); do find "$h" \( -name "*.rhosts" -o -name ".git-credentials" -o -name ".*history" \) -maxdepth 1 -exec ls -la {} \; ;'

  #looking for credentials in /etc/fstab and /etc/mtab
  lse_test "fst120" "0" \
    "Are there any credentials in fstab/mtab?" \
    'grep -E "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab'

  #check if current user has mail
  lse_test "fst130" "1" \
    "Does '$lse_user' have mail?" \
    'ls -l "/var/mail/$lse_user"'

  #check if we can access other users mail mail
  lse_test "fst140" "0" \
    "Can we access other users mail?" \
    'for f in /var/mail/*; do [ "$f" != "/var/mail/$lse_user" ] && [ -r "$f" ] && echo "$f"; done'

  #check for code repositories
  lse_test "fst150" "1" \
    "Looking for GIT/SVN repositories" \
    'find / \( -name ".git" -o -name ".svn" \)'

  #files owned by user
  lse_test "fst500" "2" \
    "Files owned by user '$lse_user'" \
    'find / -user $lse_user -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \;'

  #check for SSH files anywhere
  lse_test "fst510" "2" \
    "SSH files anywhere" \
    'find / \( -name "*id_dsa*" -o -name "*id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} \;'

  #dump hosts.equiv file
  lse_test "fst520" "2" \
    "Check hosts.equiv file and its contents" \
    'find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null \; -exec cat {} \;'

  #list nfs shares
  lse_test "fst530" "2" \
    "List NFS server shares" \
    'ls -la /etc/exports; cat /etc/exports'

  #dump fstab
  lse_test "fst540" "2" \
    "Dump fstab file" \
    'cat /etc/fstab'
}


#######################################################################( system
lse_run_tests_system() {
  lse_header "sys" "system"

  #who is logged in
  lse_test "sys000" "2" \
    "Who is logged in" \
    'w'

  #last logged in users
  lse_test "sys010" "2" \
    "Last logged in users" \
    'last'

  #check if /etc/passwd has the hashes (old system)
  lse_test "sys020" "0" \
    "Does the /etc/passwd have hashes?" \
    'grep -v "^[^:]*:[x]" /etc/passwd'

  #check if we can read any shadow file
  for s in 'shadow' 'shadow-' 'shadow~' 'master.passwd'; do
    lse_test "sys030" "0" \
      "Can we read /etc/$s file?" \
      'cat /etc/$s'
  done

  #check for superuser accounts
  lse_test "sys040" "1" \
    "Check for other superuser accounts" \
    'for u in $(cut -d: -f1 /etc/passwd); do [ $(id -u $u) == 0 ] && echo $u; done | grep -v root'

  #can root log in via SSH
  lse_test "sys050" "1" \
    "Can root user log in via SSH?" \
    'grep -E "^[[:space:]]*PermitRootLogin " /etc/ssh/sshd_config | grep -E "(yes|without-password)"'
    
  #list available shells
  lse_test "sys060" "2" \
    "List available shells" \
    'cat /etc/shells'

  #system umask
  lse_test "sys070" "2" \
    "System umask in /etc/login.defs" \
    'grep "^UMASK" /etc/login.defs'

  #system password policies
  lse_test "sys080" "2" \
    "System password policies in /etc/login.defs" \
    'grep "^PASS_MAX_DAYS\|^PASS_MIN_DAYS\|^PASS_WARN_AGE\|^ENCRYPT_METHOD" /etc/login.defs'
}


#####################################################################( security
lse_run_tests_security() {
  lse_header "sec" "security"

  #check if selinux is present
  lse_test "sec000" "1" \
    "Is SELinux present?" \
    'sestatus'

  #get all binaries with capabilities
  lse_test "sec010" "1" \
    "List files with capabilities" \
    'getcap -r /' \
    "" \
    "lse_cap_bin"

  #check if we can write an a binary with capabilities
  lse_test "sec020" "0" \
    "Can we write to a binary with caps?" \
    'for b in $(echo -e "$lse_cap_bin" | cut -d" " -f1); do [ -w "$b" ] && echo "$b"; done'

  #check if we have all capabilities in any binary
  lse_test "sec030" "0" \
    "Do we have all caps in any binary?" \
    'echo -e "$lse_cap_bin" | grep -v "cap_"'

  #search /etc/security/capability.conf for users associated capapilies
  lse_test "sec040" "1" \
    "Users with associated capabilities" \
    'grep -v "^#\|none\|^$" /etc/security/capability.conf' \
    "" \
    "lse_user_caps"

  #does user have capabilities
  lse_test "sec050" "0" \
    "Does current user have capabilities?" \
    'echo -e "$lse_user_caps" | grep "$lse_user"' \
    "sec040"
}


##############################################################( recurrent tasks 
lse_run_tests_recurrent_tasks() {
  lse_header "ret" "recurrent tasks"

  ## CRON
  #user crontab
  lse_test "ret000" "1" \
    "User crontab" \
    'crontab -l | grep -Ev "^#"'

  #cron tasks writable by user
  lse_test "ret010" "0" \
    "Cron tasks writable by user" \
    'find -L /etc/cron* /etc/anacron /var/spool/cron -writable' \

  #list cron jobs
  lse_test "ret020" "1" \
    "Cron jobs" \
    'grep -ERv "^(#|$)" /etc/crontab /etc/cron.d/ /etc/anacrontab'

  #can we read other user crontabs?
  lse_test "ret030" "1" \
    "Can we read user crontabs" \
    'ls -la /var/spool/cron/crontabs/*'

  #can we list other user cron tasks? (you need privileges for this, so if you can something is fishy)
  lse_test "ret040" "1" \
    "Can we list other user cron tasks?" \
    'for u in $(cut -d: -f 1 /etc/passwd); do [ "$u" != "$lse_user" ] && crontab -l -u "$u"; done'

  #can we write to executable paths present in cron tasks?
  lse_test "ret050" "0" \
    "Can we write to executable paths present in cron jobs" \
    'for uw in $lse_user_writable; do [ -f "$uw" ] && [ -x "$uw" ] && grep -R "$uw" /etc/crontab /etc/cron.d/ /etc/anacrontab ; done' \
    "fst000"

  #can we write to any paths present in cron tasks?
  lse_test "ret060" "1" \
    "Can we write to any paths present in cron jobs" \
    'for uw in $lse_user_writable; do grep -R "$uw" /etc/crontab /etc/cron.d/ /etc/anacrontab ; done | sort  | uniq' \
    "fst000"

  #list cron files
  lse_test "ret400" "2" \
    "Cron files" \
    'ls -la /etc/cron*'


  ## Systemd Timers
  #user timers
  lse_test "ret500" "1" \
    "User systemd timers" \
    'systemctl --user list-timers --all | grep -Ev "(^$|timers listed)"'

  #can we write in any system timer?
  lse_test "ret510" "0" \
    "Can we write in any system timer?" \
    'echo -e "$lse_user_writable" | grep -E "\.timer$"' \
    "fst000"

  #system timers
  lse_test "ret900" "2" \
    "Systemd timers" \
    'systemctl list-timers --all'
}


######################################################################( network
lse_run_tests_network() {
  lse_header "net" "network"

  #services listening only on localhost
  lse_test "net000" "1" \
    "Services listening only on localhost" \
    '(ss -tunlp || netstat -tunlp)2>/dev/null | grep "127.0.0.1:"'

  #can we execute tcpdump
  lse_test "net010" "0" \
    "Can we sniff traffic with tcpdump?" \
    '(tcpdump -i lo -n 2>&1 & pid=$!;sleep 0.2;kill $pid)2>/dev/null | grep -i "listening on lo"'

  #nic information
  lse_test "net500" "2" \
    "NIC and IP information" \
    'ifconfig -a || ip a'

  #routing table
  lse_test "net510" "2" \
    "Routing table" \
    'route -n || ip r'

  #arp table
  lse_test "net520" "2" \
    "ARP table" \
    'arp -an || ip n'

  #nameservers
  lse_test "net530" "2" \
    "Namerservers" \
    'grep "nameserver" /etc/resolv.conf'

  #systemd nameservers
  lse_test "net540" "2" \
    "Systemd Nameservers" \
    'systemd-resolve --status || systemd-resolve --user --status'

  #listening TCP
  lse_test "net550" "2" \
    "Listening TCP" \
    'netstat -tnlp || ss -tnlp'
  
  #listening UDP
  lse_test "net560" "2" \
    "Listening UDP" \
    'netstat -unlp || ss -unlp'
}


#####################################################################( services
lse_run_tests_services() {
  lse_header "srv" "services"

  ## System-V
  #check write permissions in init.d/* inetd.conf xinetd.conf
  lse_test "srv000" "0" \
    "Can we write in service files?" \
    'echo -e "$lse_user_writable" | grep -E "^/etc/(init/|init\.d/|rc\.d/|rc[0-9S]\.d/|rc\.local|inetd\.conf|xinetd\.conf|xinetd\.d/)"' \
    "fst000"

  #check write permissions for binaries involved in services
  lse_test "srv010" "0" \
    "Can we write in binaries executed by services?" \
    'for b in $(grep -ERvh "^#" /etc/inetd.conf /etc/xinetd.conf /etc/xinetd.d/ /etc/init.d/ /etc/rc* 2>/dev/null | tr -s "[[:space:]]" "\n" | grep -E "^/" | grep -Ev "^/(dev|run|sys|proc|tmp)/" | sort | uniq); do [ -x "$b" ] && [ -w "$b" ] && echo "$b" done'

  #init.d files NOT belonging to root
  lse_test "srv020" "1" \
    "Files in /etc/init.d/ not belonging to root" \
    'find /etc/init.d/ \! -uid 0 -type f | xargs -r ls -la'

  #rc.d/init.d files NOT belonging to root!
  lse_test "srv030" "1" \
    "Files in /etc/rc.d/init.d not belonging to root" \
    'find /etc/rc.d/init.d \! -uid 0 -type f | xargs -r ls -la'

  # upstart scripts not belonging to root
  lse_test "srv040" "1" \
    "Upstart files not belonging to root" \
    'find /etc/init \! -uid 0 -type f | xargs -r ls -la'

  #/usr/local/etc/rc.d files NOT belonging to root!
  lse_test "srv050" "1" \
    "Files in /usr/local/etc/rc.d not belonging to root" \
    'find /usr/local/etc/rc.d \! -uid 0 -type f | xargs -r ls -la'

  #contents of inetd.conf
  lse_test "srv400" "2" \
    "Contents of /etc/inetd.conf" \
    'cat /etc/inetd.conf'

  #xinetd info
  lse_test "srv410" "2" \
    "Contents of /etc/xinetd.conf" \
    'cat /etc/xinetd.conf'

  #check xinetd.d and permissions
  lse_test "srv420" "2" \
    "List /etc/xinetd.d if used" \
    'grep "/etc/xinetd.d" /etc/xinetd.conf ; ls -la /etc/xinetd.d'

  #permissions of init.d scripts
  lse_test "srv430" "2" \
    "List /etc/init.d/ permissions" \
    'ls -la /etc/init.d'

  #rc.d/init.d permissions
  lse_test "srv440" "2" \
    "List /etc/rc.d/init.d permissions" \
    'ls -la /etc/rc.d/init.d'

  #usr/rc.d permissions
  lse_test "srv450" "2" \
    "List /usr/local/etc/rc.d permissions" \
    'ls -la /usr/local/etc/rc.d'

  # init permissions
  lse_test "srv460" "2" \
    "List /etc/init/ permissions" \
    'ls -la /etc/init/'

  ## Systemd
  #check write permissions in systemd services
  lse_test "srv500" "0" \
    "Can we write in systemd service files?" \
    'echo -e "$lse_user_writable" | grep -E "^/(etc/systemd/|lib/systemd/).+\.service$"' \
    "fst000"

  #check write permissions for binaries involved in systemd services
  lse_test "srv510" "0" \
    "Can we write in binaries executed by systemd services?" \
    'for b in $(grep -ERh "^Exec" /etc/systemd/ /lib/systemd/ 2>/dev/null | tr "=" "\n" | tr -s "[[:space:]]" "\n" | grep -E "^/" | grep -Ev "^/(dev|run|sys|proc|tmp)/" | sort | uniq); do [ -x "$b" ] && [ -w "$b" ] && echo "$b" done'

  # systemd files not belonging to root
  lse_test "srv520" "1" \
    "Systemd files not belonging to root" \
    'find /lib/systemd/ /etc/systemd \! -uid 0 -type f | xargs -r ls -la'

  # systemd permissions
  lse_test "srv900" "2" \
    "Systemd config files permissions" \
    'ls -lthR /lib/systemd/ /etc/systemd/'
}


####################################################################( processes
lse_run_tests_processes() {
  lse_header "pro" "processes"

  #lookup process binaries
  lse_proc_bin=`(ps -eo comm | sort | uniq | xargs which)2>/dev/null`

  #check if we have wire permissions in any process binary
  lse_test "pro000" "0" \
    "Can we write in any process binary?" \
    'for b in $lse_proc_bin; do [ -w "$b" ] && echo $b; done'

  lse_test "pro010" "1" \
    "Processes running with root permissions" \
    'ps -u root -U root -f | grep -Ev "\[[[:alnum:]]"'

  #running processes
  lse_test "pro500" "2" \
    "Running processes" \
    'ps auxf'

  #list running process binaries and their permissions
  lse_test "pro510" "2" \
    "Running process binaries and permissions" \
    'echo -e "$lse_proc_bin" | xargs -n1 ls -l'
}


#####################################################################( software
lse_run_tests_software() {
  lse_header "sof" "software"

  #checks to see if root/root will get us a connection
  lse_test "sof000" "0" \
    "Can we connect to MySQL with root/root credentials?" \
    'mysqladmin -uroot -proot version'

  #checks to see if we can connect as root without password
  lse_test "sof010" "0" \
    "Can we connect to MySQL as root without password?" \
    'mysqladmin -uroot version'

  #checks to see if we can connect to postgres templates without password
  lse_test "sof020" "0" \
    "Can we connect to PostgreSQL template0 as postgres and no pass?" \
    'psql -U postgres template0 -c "select version()" | grep version'
  lse_test "sof020" "0" \
    "Can we connect to PostgreSQL template1 as postgres and no pass?" \
    'psql -U postgres template1 -c "select version()" | grep version'
  lse_test "sof020" "0" \
    "Can we connect to PostgreSQL template0 as psql and no pass?" \
    'psql -U pgsql template0 -c "select version()" | grep version'
  lse_test "sof020" "0" \
    "Can we connect to PostgreSQL template1 as psql and no pass?" \
    'psql -U pgsql template1 -c "select version()" | grep version'

  #installed apache modules
  lse_test "sof030" "1" \
    "Installed apache modules" \
    'apache2ctl -M; httpd -M'

  #find htpassword files
  lse_test "sof040" "0" \
    "Found any .htpasswd files?" \
    'find / -name "*.htpasswd" -print -exec cat {} \;'

  #sudo version - check to see if there are any known vulnerabilities with this
  lse_test "sof500" "2" \
    "Sudo version" \
    'sudo -V | grep "Sudo version"'

  #mysql details - if installed
  lse_test "sof510" "2" \
    "MySQL version" \
    'mysql --version'

  #postgres details - if installed
  lse_test "sof520" "2" \
    "Postgres version" \
    'psql -V'

  #apache details - if installed
  lse_test "sof530" "2" \
    "Apache version" \
    'apache2 -v; httpd -v'
}


###################################################################( containers
lse_run_tests_containers() {
  lse_header "ctn" "containers"

  #check to see if we are in a docker container
  lse_test "ctn000" "1" \
    "Are we in a docker container?" \
    'grep -i docker /proc/self/cgroup; find / -name "*dockerenv*" -exec ls -la {} \;'

  #check to see if current host is running docker services
  lse_test "ctn010" "1" \
    "Is docker available?" \
    'docker --version; docker ps -a'

  #is user a member of the docker group
  lse_test "ctn020" "0" \
    "Is the user a member of the 'docker' group?" \
    'groups | grep -o docker'

  #check to see if we are in an lxc container
  lse_test "ctn200" "1" \
    "Are we in a lxc container?" \
    'grep -a container=lxc /proc/1/environ | tr -d "\0"'

  #is user a member of any lxd/lxc group
  lse_test "ctn210" "0" \
    "Is the user a member of any lxc/lxd group?" \
    'groups | grep  "lxc|lxd"'
}
#
##)

#( Main
while getopts "hcil:s:" option; do
  case "${option}" in
    c) lse_color=false;;
    i) lse_interactive=false;;
    l) lse_set_level "${OPTARG}";;
    s) lse_selection="${OPTARG//,/ }";;
    h) lse_help; exit 0;;
    *) lse_help; exit 1;;
  esac
done

#trap to exec on SIGINT
trap "lse_exit 1" SIGINT

lse_request_information
lse_show_info
PATH="$PATH:/sbin:/usr/sbin" #fix path just in case

lse_run_tests_users
lse_run_tests_sudo
lse_run_tests_filesystem
lse_run_tests_system
lse_run_tests_security
lse_run_tests_recurrent_tasks
lse_run_tests_network
lse_run_tests_services
lse_run_tests_processes
lse_run_tests_software
lse_run_tests_containers

lse_exit 0
#)
