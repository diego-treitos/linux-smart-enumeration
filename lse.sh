#!/bin/sh
# shellcheck disable=1003,1091,2006,2016,2034,2039
# vim: set ts=2 sw=2 sts=2 fdm=marker fmr=#(,#) et:

# Author: Diego Blanco <diego.blanco@treitos.com>
# GitHub: https://github.com/diego-treitos/linux-smart-enumeration
#
lse_version="4.6nw"

##( Colors
#
#( fg
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
##)
#( bg
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
##)
#( special
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
##)
#)

##( Globals
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
lse_distro_codename="" # retrieved below with lse_get_distro_codename

# lse
lse_passed_tests=""
lse_executed_tests=""
lse_DEBUG=false
lse_procmon_data=`mktemp`
lse_procmon_lock=`mktemp`
lse_cve_tmp=''

# printf
printf "%s" "$reset" | grep -q '\\' && alias printf="env printf"

#( internal data
lse_common_setuid="
/bin/fusermount
/bin/mount
/bin/ntfs-3g
/bin/ping
/bin/ping6
/bin/su
/bin/umount
/lib64/dbus-1/dbus-daemon-launch-helper
/sbin/mount.ecryptfs_private
/sbin/mount.nfs
/sbin/pam_timestamp_check
/sbin/pccardctl
/sbin/unix2_chkpwd
/sbin/unix_chkpwd
/usr/bin/Xorg
/usr/bin/arping
/usr/bin/at
/usr/bin/beep
/usr/bin/chage
/usr/bin/chfn
/usr/bin/chsh
/usr/bin/crontab
/usr/bin/expiry
/usr/bin/firejail
/usr/bin/fusermount
/usr/bin/fusermount-glusterfs
/usr/bin/fusermount3
/usr/bin/gpasswd
/usr/bin/kismet_capture
/usr/bin/mount
/usr/bin/mtr
/usr/bin/newgidmap
/usr/bin/newgrp
/usr/bin/newuidmap
/usr/bin/ntfs-3g
/usr/bin/passwd
/usr/bin/pkexec
/usr/bin/pmount
/usr/bin/procmail
/usr/bin/pumount
/usr/bin/staprun
/usr/bin/su
/usr/bin/sudo
/usr/bin/sudoedit
/usr/bin/traceroute6.iputils
/usr/bin/umount
/usr/bin/weston-launch
/usr/lib/chromium-browser/chrome-sandbox
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/dbus-1/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib/pt_chown
/usr/lib/snapd/snap-confine
/usr/lib/spice-gtk/spice-client-glib-usb-acl-helper
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/xorg/Xorg.wrap
/usr/libexec/Xorg.wrap
/usr/libexec/abrt-action-install-debuginfo-to-abrt-cache
/usr/libexec/cockpit-session
/usr/libexec/dbus-1/dbus-daemon-launch-helper
/usr/libexec/gstreamer-1.0/gst-ptp-helper
/usr/libexec/openssh/ssh-keysign
/usr/libexec/polkit-1/polkit-agent-helper-1
/usr/libexec/polkit-agent-helper-1
/usr/libexec/pt_chown
/usr/libexec/qemu-bridge-helper
/usr/libexec/spice-client-glib-usb-acl-helper
/usr/libexec/spice-gtk-x86_64/spice-client-glib-usb-acl-helper
/usr/local/share/panasonic/printer/bin/L_H0JDUCZAZ
/usr/sbin/exim4
/usr/sbin/grub2-set-bootflag
/usr/sbin/mount.nfs
/usr/sbin/mtr-packet
/usr/sbin/pam_timestamp_check
/usr/sbin/pppd
/usr/sbin/pppoe-wrapper
/usr/sbin/suexec
/usr/sbin/unix_chkpwd
/usr/sbin/userhelper
/usr/sbin/usernetctl
/usr/sbin/uuidd
"
#)
#( regex rules for common setuid
lse_common_setuid="$lse_common_setuid
/snap/core.*
/var/tmp/mkinitramfs.*
"
#)
#( critical writable files
lse_critical_writable="
/etc/apache2/apache2.conf
/etc/apache2/httpd.conf
/etc/bash.bashrc
/etc/bash_completion
/etc/bash_completion.d/*
/etc/environment
/etc/environment.d/*
/etc/hosts.allow
/etc/hosts.deny
/etc/httpd/conf/httpd.conf
/etc/httpd/httpd.conf
/etc/incron.conf
/etc/incron.d/*
/etc/logrotate.d/*
/etc/modprobe.d/*
/etc/pam.d/*
/etc/passwd
/etc/php*/fpm/pool.d/*
/etc/php/*/fpm/pool.d/*
/etc/profile
/etc/profile.d/*
/etc/rc*.d/*
/etc/rsyslog.d/*
/etc/shadow
/etc/skel/*
/etc/sudoers
/etc/sudoers.d/*
/etc/supervisor/conf.d/*
/etc/supervisor/supervisord.conf
/etc/sysctl.conf
/etc/sysctl.d/*
/etc/uwsgi/apps-enabled/*
/root/.ssh/authorized_keys
"
#critical writable directories
lse_critical_writable_dirs="
/etc/bash_completion.d
/etc/cron.d
/etc/cron.daily
/etc/cron.hourly
/etc/cron.weekly
/etc/environment.d
/etc/logrotate.d
/etc/modprobe.d
/etc/pam.d
/etc/profile.d
/etc/rsyslog.d/
/etc/sudoers.d/
/etc/sysctl.d
/root
"
#)
#( CVE list (populated by the lse packager)
lse_cve_list="
" #CVElistMARKER
#)
#)

##( Options
lse_color=true
lse_alt_color=false
lse_interactive=true
lse_proc_time=60
lse_level=0 #Valid levels 0:default, 1:interesting, 2:all
lse_selection="" #Selected tests to run. Empty means all.
lse_find_opts='-path /proc -prune -o -path /sys -prune -o -path /dev -prune -o' #paths to exclude from searches
lse_grep_opts='--color=always'
#)

##( Lib
cecho() { #(
  if $lse_color; then
    printf "%b" "$@"
  else
    # If color is disabled we remove it
    printf "%b" "$@" | sed 's/\x1B\[[0-9;]\+[A-Za-z]//g'
  fi
} #)
lse_recolor() { #(
  o_white="$white"
  o_lyellow="$lyellow"
  o_grey="$grey"
  o_lred="$lred"
  o_lgreen="$lgreen"
  o_lcyan="$lcyan"

  white="$o_grey"
  lyellow="$o_lred"
  grey="$lgrey"
  lred="$red"
  lgreen="$b_lgreen$black"
  lcyan="$cyan"
} #)
lse_error() { #(
  cecho "${red}ERROR: ${reset}$*\n" >&2
} #)
lse_exclude_paths() { #(
  local IFS="
"
  for p in `printf "%s" "$1" | tr ',' '\n'`; do
    [ "`printf \"%s\" \"$p\" | cut -c1`" = "/" ] || lse_error "'$p' is not an absolute path."
    p="${p%%/}"
    lse_find_opts="$lse_find_opts -path ${p} -prune -o"
  done
} #)
lse_set_level() { #(
  case "$1" in
    0|1|2)
      lse_level=$(($1))
      ;;
    *)
      lse_error "Invalid level."
      exit 1
      ;;
  esac
} #)
lse_help() { #(
  echo "Use: $0 [options]"
  echo
  echo " OPTIONS"
  echo "  -c           Disable color"
  echo "  -C           Use alternative color scheme"
  echo "  -i           Non interactive mode"
  echo "  -h           This help"
  echo "  -l LEVEL     Output verbosity level"
  echo "                 0: Show highly important results. (default)"
  echo "                 1: Show interesting results."
  echo "                 2: Show all gathered information."
  echo "  -s SELECTION Comma separated list of sections or tests to run. Available"
  echo "               sections:"
  echo "                 usr: User related tests."
  echo "                 sud: Sudo related tests."
  echo "                 fst: File system related tests."
  echo "                 sys: System related tests."
  echo "                 sec: Security measures related tests."
  echo "                 ret: Recurrent tasks (cron, timers) related tests."
  echo "                 net: Network related tests."
  echo "                 srv: Services related tests."
  echo "                 pro: Processes related tests."
  echo "                 sof: Software related tests."
  echo "                 ctn: Container (docker, lxc) related tests."
  echo "                 cve: CVE related tests."
  echo "               Specific tests can be used with their IDs (i.e.: usr020,sud)"
  echo "  -e PATHS     Comma separated list of paths to exclude. This allows you"
  echo "               to do faster scans at the cost of completeness"
  echo "  -p SECONDS   Time that the process monitor will spend watching for"
  echo "               processes. A value of 0 will disable any watch (default: 60)"
  echo "  -S           Serve the lse.sh script in this host so it can be retrieved"
  echo "               from a remote host."
} #)
lse_ask() { #(
  local question="$1"
  # We use stderr to print the question
  cecho "${white}${question}: ${reset}" >&2
  read -r answer
  case "$answer" in
    y|Y|yes|Yes|ok|Ok|true|True)
      return 0
      ;;
    *)
      echo "$answer"
      return 1
      ;;
  esac
} #)
lse_request_information() { #(
  if $lse_interactive; then
  cecho "${grey}---\n"
    [ -z "$lse_user" ] && lse_user=`lse_ask "Could not find current user name. Current user?"`
    lse_pass=`lse_ask "If you know the current user password, write it here to check sudo privileges"`
  cecho "${grey}---\n"
  fi
} #)
lse_test_passed() { #(
  # Checks if a test passed by ID
  local id="$1"
  for i in $lse_passed_tests; do
    [ "$i" = "$id" ] && return 0
  done
  return 1
} #)
lse_test() { #(
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
      if [ "$s" = "$id" ] || [ "$s" = "`printf \"%s\" \"$id\" | cut -c1-3`" ]; then
        sel_match=true
      fi
    done
    $sel_match || return 0
  fi

  # DEBUG messages
  $lse_DEBUG && cecho "${lmagenta}DEBUG: ${lgreen}Executing: ${reset}$cmd\n"

  # Print name and line
  cecho "${white}[${l}${white}] ${grey}${id}${white} $name${grey}"
  for i in $(seq $((${#id}+${#name}+10)) 79); do
    echo -n "."
  done

  # Check dependencies
  local non_met_deps=""
  for d in $deps; do
    lse_test_passed "$d" || non_met_deps="$non_met_deps $d"
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

  # If level is 2 and lse_level is less than 2, then we do not execute
  # level 2 tests unless their output needs to be assigned to a variable
  if [ $level -ge 2 ] && [ $lse_level -lt 2 ] && [ -z "$var" ]; then
    cecho " ${grey}skip\n"
    return 1
  else
    if $lse_DEBUG; then
      output="`eval "$cmd" 2>&1`"
    else
      # Execute command if this test's level is in scope
      output="`eval "$cmd" 2>/dev/null`"
    # Assign variable if available
    fi
    [ "$var" ] && [ "$output" ] && readonly "${var}=$output"
    # Mark test as executed
    lse_executed_tests="$lse_executed_tests $id"
  fi

  if [ -z "$output" ]; then
    cecho " ${grey}nope${reset}\n"
    return 1
  else
    lse_passed_tests="$lse_passed_tests $id"
    cecho "${r} yes!${reset}\n"
    if [ $lse_level -ge $level ]; then
      cecho "${grey}---$reset\n"
      echo "$output"
      cecho "${grey}---$reset\n"
    fi
    return 0
  fi
} #)
lse_show_info() { #(
  echo
  cecho "${lcyan} LSE Version:${reset} $lse_version\n"
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
  cecho  "${green}=====================(${yellow} Current Output Verbosity Level: ${cyan}$lse_level ${green})======================${reset}"
  echo
} #)
lse_serve() { #(
  # get port
  which nc >/dev/null || lse_error "Could not find 'nc' netcat binary."

  local_ips="`ip a | grep -Eo "inet ([0-9]{1,3}\.){3}[0-9]{1,3}" | cut -d' ' -f2`"

  # Get a valid and non used port
  port=`od -An -N2 -i /dev/random|grep -Eo '[0-9]+'`
  port_valid=true
  while true; do
    for ip in $local_ips; do
      nc -z "$ip" "$port" && port_valid=false
    done
    if [ $((port)) -lt 1024 ] || [ $((port)) -gt 65500 ]; then
      port_valid=false
    fi
    $port_valid && break
    port=`od -An -N2 -i /dev/random|grep -Eo '[0-9]+'`
  done

  echo
  cecho " Serving ${white}Linux Smart Enumeration${reset} on port ${blue}$port${reset}.\n"
  echo
  cecho " Depending on your IP and available tools, some of these commands should download it in a remote host:\n"
  for ip in $local_ips; do
    [ "$ip" = "127.0.0.1" ] && continue
    echo
    cecho "${reset} [${blue}$ip${reset}]\n"
    cecho "${green}   * ${white}nc ${reset}              $ip $port   > lse.sh </dev/null; chmod 755 lse.sh\n"
    cecho "${green}   * ${white}curl ${reset}--http0.9  '$ip:$port' -o lse.sh; chmod 755 lse.sh\n"
    cecho "${green}   * ${white}wget ${reset}           '$ip:$port' -O lse.sh; chmod 755 lse.sh\n"
    cecho "${green}   * ${white}exec 3<>/dev/tcp/${reset}$ip/$port;printf '\\\\n'>&3;cat<&3>lse.sh;exec 3<&-;chmod 755 lse.sh\n"
  done
  # try nc with '-N' (openbsd), then ncat and then use '-q0' (traditional)
  nc -l -N -p "$port" < "$0" >/dev/null 2>/dev/null || nc -l --send-only -p "$port" < "$0" >/dev/null 2>/dev/null || nc -l -q0 -p "$port" < "$0" >/dev/null
} #)
lse_header() { #(
  local id="$1"
  shift
  local title="$*"
  local text="${magenta}"

  # Filter selected tests
  if [ "$lse_selection" ]; then
    local sel_match=false
    for s in $lse_selection; do
      if [ "`printf \"%s\" \"$s\"|cut -c1-3`" = "$id" ]; then
        sel_match=true
        break
      fi
    done
    $sel_match || return 0
  fi

  for i in $(seq ${#title} 70); do
    text="$text="
  done
  text="$text(${green} $title ${magenta})====="
  cecho "$text${reset}\n"
} #)
lse_exit() { #(
  local ec=1
  local text="\n${magenta}=================================="
  [ "$1" ] && ec=$1
  text="$text(${green} FINISHED ${magenta})=================================="
  cecho "$text${reset}\n"
  rm -f "$lse_procmon_data"
  rm -f "$lse_procmon_lock"
  rm -f "$lse_cve_tmp"
  exit "$ec"
} #)
lse_procmon() { #(
  # monitor processes
  #NOTE: The first number will be the number of occurrences of a process due to
  #      uniq -c
  while [ -f "$lse_procmon_lock" ]; do
    ps -ewwwo start_time,pid,user:50,args
    sleep 0.001
  done | grep -v 'ewwwo start_time,pid,user:50,args' | sed 's/^ *//g' | tr -s '[:space:]' | grep -v "^START" | grep -Ev '[^ ]+ [^ ]+ [^ ]+ \[' | sort -Mr | uniq -c | sed 's/^ *//g' > "$lse_procmon_data"
} #)
lse_proc_print() { #(
  # Pretty prints output from lse_procmom received via stdin
  if $lse_color; then
    printf "${green}%s %8s %8s %s\n" "START" "PID" "USER" "COMMAND"
  else
    printf "%s %8s %8s %s\n" "START" "PID" "USER" "COMMAND"
  fi
  while read -r l; do
    p_num=`echo "$l" | cut -d" " -f1`
    p_time=`echo "$l" | cut -d" " -f2`
    p_pid=`echo "$l" | cut -d" " -f3`
    p_user=`echo "$l" | cut -d" " -f4`
    p_args=`echo "$l" | cut -d" " -f5-`

    if $lse_color; then
      if [ $((p_num)) -lt 20 ]; then # few times probably periodic
        printf "${red}%s ${reset}%8s ${yellow}%8s ${red}%s\n" "$p_time" "$p_pid" "$p_user" "$p_args"
      else
        printf "${magenta}%s ${reset}%8s ${yellow}%8s ${reset}%s\n" "$p_time" "$p_pid" "$p_user" "$p_args"
      fi
    else
      printf "%s %8s %8s %s\n" "$p_time" "$p_pid" "$p_user" "$p_args"
    fi
  done
} #)
lse_get_distro_codename() { #(
  # Get the distribution name
  #
  # ubuntu, debian, centos, redhat, opsuse, fedora, rocky
  local distro="${grey}unknown${reset}"
  if type lsb_release >/dev/null 2>&1; then
    distro=`lsb_release -is`
  elif [ -f /etc/os-release ]; then
    distro=`grep -E '^ID=' /etc/os-release | cut -f2 -d=`
    echo "$distro" | grep -qi opensuse && distro=opsuse
  elif [ -f /etc/redhat-release ]; then
    grep -qi "centos"  /etc/redhat-release && distro=centos
    grep -qi "fedora"  /etc/redhat-release && distro=fedora
    grep -qi "red hat" /etc/redhat-release && distro=redhat
    grep -qi "rocky"   /etc/redhat-release && distro=rocky
  fi
  echo -n "$distro" | tr '[:upper:]' '[:lower:]' | tr -d \"\'
} #)
lse_is_version_bigger() { #(
  # check if version v1 is bigger than v2
  local v1="$1"; local v2="$2" ; local vc
  [ "$v1" = "$v2" ] && return 1 # equal is not bigger
  vc="`printf "%s\n%s\n" "$v1" "$v2" | sort -rV | head -n1`"
  [ "$v1" = "$vc" ] && return 0
  return 1
} #)
lse_get_pkg_version() { #(
  # get package version depending on distro
  # returns 2 if distro is unknown
  # returns 1 if package is not installed (or doesn't exist)
  # returns 0 on success, and prints out the package version
  pkg_name="$1"
  case "$lse_distro_codename" in
    debian|ubuntu)
      pkg_version=`dpkg -l "$pkg_name" 2>/dev/null | grep -E '^ii' | tr -s ' ' | cut -d' ' -f3`
      ;;
    centos|redhat|fedora|opsuse|rocky)
      pkg_version=`rpm -q "$pkg_name" 2>/dev/null`
      pkg_version="${pkg_version##$pkg_name-}"
      pkg_version=`echo "$pkg_version" | sed -E 's/\.(aarch64|armv7hl|i686|noarch|ppc64le|s390x|x86_64)$//'`
      ;;
    *)
      return 2
      ;;
  esac
  [ -z "$pkg_version" ] && return 1
  printf "%s" "$pkg_version"
  return 0
} #)
#)
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
    'grep $lse_grep_opts -E "^(adm|admin|root|sudo|wheel)" /etc/group | grep $lse_grep_opts -E "(:|,)$lse_user"'

  #other users in an administrative group
  lse_test "usr020" "1" \
    "Are there other users in administrative groups?" \
    'grep $lse_grep_opts -E "^(adm|admin|root|sudo|wheel)" /etc/group | grep -Ev ":$|:$lse_user$" | grep $lse_grep_opts -Ei ":[,a-z_-]+\$"'

  #other users with shell
  lse_test "usr030" "1" \
    "Other users with shell" \
    'grep $lse_grep_opts -E ":/[a-z/]+sh\$" /etc/passwd' \
    "" \
    "lse_shell_users"

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

  #find defined PATHs
  lse_test "usr070" "1" \
    "PATH variables defined inside /etc" \
    'for p in `grep -ERh "^ *PATH=.*" /etc/ 2> /dev/null | tr -d \"\'"'"' | cut -d= -f2 | tr ":" "\n" | sort -u`; do [ -d "$p" ] && echo "$p";done' \
    "" \
    "lse_exec_paths"

  #check if . is in PATHs
  lse_test "usr080" "0" \
    "Is '.' in a PATH variable defined inside /etc?" \
    'for ep in $lse_exec_paths; do [ "$ep" = "." ] && grep -ER "^ *PATH=.*" /etc/ 2> /dev/null | tr -d \"\'"'"' | grep -E "[=:]\.([:[:space:]]|\$)";done' \
    "usr070"
}
#)

#########################################################################( sudo
lse_run_tests_sudo() {
  lse_header "sud" "sudo"

  #variables for sudo checks
  lse_sudo=false
  lse_sudo_commands=""

  #can we sudo without supplying a password
  lse_test "sud000" "0" \
    "Can we sudo without a password?" \
    'echo "" | sudo -nS id' && lse_sudo=true

  #can we list sudo commands without supplying a password
  $lse_sudo || \
    lse_test "sud010" "0" \
    "Can we list sudo commands without a password?" \
    'echo "" | sudo -nS -l' \
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
    "Can we read sudoers files?" \
    'grep -R "" /etc/sudoers*'

  #check users that sudoed in the past
  lse_test "sud050" "1" \
    "Do we know if any other users used sudo?" \
    'for uh in $(cut -d: -f1,6 /etc/passwd); do [ -f "${uh##*:}/.sudo_as_admin_successful" ] && echo "${uh%%:*}"; done'
}
#)

##################################################################( file system
lse_run_tests_filesystem() {
  lse_header "fst" "file system"

  #writable files outside user's home. NOTE: Does not check if user can write in symlink destination (performance reasons: -L implies -noleaf)
  lse_test "fst000" "1" \
    "Writable files outside user's home" \
    'find / -path "$lse_home" -prune -o $lse_find_opts -not -type l -writable -print;
    # Add symlinks owned by the user (so the user can change where they point)
    find  / -path "$lse_home" -prune -o $lse_find_opts -type l -user $lse_user -print' \
    "" \
    "lse_user_writable"

  #get setuid binaries
  lse_test "fst010" "1" \
    "Binaries with setuid bit" \
    'find / $lse_find_opts -perm -4000 -type f -print' \
    "" \
    "lse_setuid_binaries"

  #uncommon setuid binaries
  lse_test "fst020" "0" \
    "Uncommon setuid binaries" \
    'local setuidbin="$lse_setuid_binaries"; local IFS="
"; for cs in ${lse_common_setuid}; do setuidbin=`printf "$setuidbin\n" | grep -Ev "^$cs$"`;done ; printf "$setuidbin\n"' \
    "fst010"

  #can we write to any setuid binary
  lse_test "fst030" "0" \
    "Can we write to any setuid binary?" \
    'for b in $lse_setuid_binaries; do [ -x "$b" ] && [ -w "$b" ] && echo "$b" ;done' \
    "fst010"

  #get setgid binaries
  lse_test "fst040" "1" \
    "Binaries with setgid bit" \
    'find / $lse_find_opts -perm -2000 -type f -print' \
    "lse_setgid_binaries"

  #uncommon setgid binaries
  lse_test "fst050" "0" \
    "Uncommon setgid binaries" \
    'printf "$lse_setgid_binaries\n" | grep -Ev "^/(bin|sbin|usr/bin|usr/lib|usr/sbin)"' \
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
    'for h in $(cut -d: -f6 /etc/passwd | sort -u | grep -Ev "^(/|/dev|/bin|/proc|/run/.*|/var/run/.*)$"); do find "$h" \( -name "*id_dsa*" -o -name "*id_rsa*" -o -name "*id_ecdsa*" -o -name "*id_ed25519*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} \; ; done'

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
    'grep $lse_grep_opts -Ei "(user|username|login|pass|password|pw|credentials)[=:]" /etc/fstab /etc/mtab'

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
    'find / $lse_find_opts \( -name ".git" -o -name ".svn" \) -print'

  #can we write to files that can give us root
  lse_test "fst160" "0" \
    "Can we write to critical files?" \
    'for uw in $lse_user_writable; do [ -f "$uw" ] && IFS="
"; for cw in ${lse_critical_writable}; do [ "$cw" = "$uw" ] && [ -w "$cw" ] && ls -l $cw; done ; done' \
    "fst000"

  #can we write to directories that can give us root
  lse_test "fst170" "0" \
    "Can we write to critical directories?" \
    'for uw in $lse_user_writable; do [ -d "$uw" ] && IFS="
"; for cw in ${lse_critical_writable_dirs}; do [ "$cw" = "$uw" ] && [ -w "$cw" ] && ls -ld $cw; done ; done' \
    "fst000"

  #can we write to directories inside PATHS
  lse_test "fst180" "0" \
    "Can we write to directories from PATH defined in /etc?" \
    'for ep in $lse_exec_paths; do [ -d "$ep" ] && [ -w "$ep" ] && ls -ld "$ep"; done' \
    "usr070"

  #can we read backups
  lse_test "fst190" "0" \
    "Can we read any backup?" \
    'find / $lse_find_opts -path /usr/lib -prune -o -path /usr/share -prune -o -regextype egrep -iregex ".*(backup|dump|cop(y|ies)|bak|bkp)[^/]*\.(sql|tgz|tar|zip)?\.?(gz|xz|bzip2|bz2|lz|7z)?" -readable -type f -exec ls -al {} \;'

  #are there possible credentials in any shell history files
  lse_test "fst200" "0" \
    "Are there possible credentials in any shell history file?" \
    'for h in .bash_history .history .histfile .zhistory; do [ -f "$lse_home/$h" ] && grep $lse_grep_opts -Ei "(user|username|login|pass|password|pw|credentials)[=: ][a-z0-9]+" "$lse_home/$h" | grep -v "systemctl"; done'

  #nfs exports with no_root_squash
  lse_test "fst210" "0" \
    "Are there NFS exports with 'no_root_squash' option?" \
    'grep $lse_grep_opts "no_root_squash" /etc/exports'

  #nfs exports with no_all_squash
  lse_test "fst220" "1" \
    "Are there NFS exports with 'no_all_squash' option?" \
    'grep $lse_grep_opts "no_all_squash" /etc/exports'

  #files owned by user
  lse_test "fst500" "2" \
    "Files owned by user '$lse_user'" \
    'find / $lse_find_opts -user $lse_user -type f -exec ls -al {} \;'

  #check for SSH files anywhere
  lse_test "fst510" "2" \
    "SSH files anywhere" \
    'find / $lse_find_opts \( -name "*id_dsa*" -o -name "*id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} \;'

  #dump hosts.equiv file
  lse_test "fst520" "2" \
    "Check hosts.equiv file and its contents" \
    'find /etc -iname hosts.equiv -exec ls -la {} 2>/dev/null \; -exec cat {} \;'

  #list nfs shares
  lse_test "fst530" "2" \
    "List NFS server shares" \
    'ls -la /etc/exports 2>/dev/null && cat /etc/exports'

  #dump fstab
  lse_test "fst540" "2" \
    "Dump fstab file" \
    'cat /etc/fstab'
}
#)

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

  #check if /etc/group has group password hashes (old system)
  lse_test "sys022" "0" \
    "Does the /etc/group have hashes?" \
    'grep -v "^[^:]*:[x]" /etc/group'

  #check if we can read any shadow file
  lse_test "sys030" "0" \
  "Can we read shadow files?" \
  'for sf in "shadow" "shadow-" "shadow~" "gshadow" "gshadow-" "master.passwd"; do [ -r "/etc/$sf" ] && printf "%s\n---\n" "/etc/$sf" && cat "/etc/$sf" && printf "\n\n";done'

  #check for superuser accounts
  lse_test "sys040" "1" \
    "Check for other superuser accounts" \
    'for u in $(cut -d: -f1 /etc/passwd); do [ $(id -u $u) = 0 ] && echo $u; done | grep -v root'

  #can root log in via SSH
  lse_test "sys050" "1" \
    "Can root user log in via SSH?" \
    'grep -E "^[[:space:]]*PermitRootLogin " /etc/ssh/sshd_config | grep -E "(yes|without-password|prohibit-password)"'

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
#)

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
    'for b in $(printf "$lse_cap_bin\n" | cut -d" " -f1); do [ -w "$b" ] && echo "$b"; done'

  #check if we have all capabilities in any binary
  lse_test "sec030" "0" \
    "Do we have all caps in any binary?" \
    'printf "$lse_cap_bin\n" | grep -v "cap_"'

  #search /etc/security/capability.conf for users associated capapilies
  lse_test "sec040" "1" \
    "Users with associated capabilities" \
    'grep -v "^#\|none\|^$" /etc/security/capability.conf' \
    "" \
    "lse_user_caps"

  #does user have capabilities
  lse_test "sec050" "0" \
    "Does current user have capabilities?" \
    'printf "$lse_user_caps\n" | grep "$lse_user"' \
    "sec040"

  #can user read the auditd log
  lse_test "sec060" "0" \
    "Can we read the auditd log?" \
    'al=/var/log/audit/audit.log; test -r "$al" && echo "tail $al:" && echo && tail "$al"'
}
#)

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
    'find -L /etc/cron* /etc/anacron /var/spool/cron -writable'

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

  #can we write to any paths present in cron tasks?
  lse_test "ret050" "1" \
    "Can we write to any paths present in cron jobs" \
    'for p in `grep --color=never -hERoi "/[a-z0-9_/\.\-]+" /etc/cron* | grep -Ev "/dev/(null|zero|random|urandom)" | sort -u`; do [ -w "$p" ] && echo "$p"; done' \
    "" \
    "lse_user_writable_cron_paths"

  #can we write to executable paths present in cron tasks?
  lse_test "ret060" "0" \
    "Can we write to executable paths present in cron jobs" \
    'for uwcp in $lse_user_writable_cron_paths; do [ -w "$uwcp" ] && [ -x "$uwcp" ] && grep $lse_grep_opts -R "$uwcp" /etc/crontab /etc/cron.d/ /etc/anacrontab ; done' \
    "ret050"

  #list cron files
  lse_test "ret400" "2" \
    "Cron files" \
    'ls -la /etc/cron*'


  ## Systemd Timers
  #user timers
  lse_test "ret500" "1" \
    "User systemd timers" \
    'systemctl --user list-timers --all | grep -iq "\.timer" && systemctl --user list-timers --all'

  #can we write in any system timer?
  lse_test "ret510" "0" \
    "Can we write in any system timer?" \
    'printf "$lse_user_writable\n" | grep -E "\.timer$"' \
    "fst000"

  #system timers
  lse_test "ret900" "2" \
    "Systemd timers" \
    'systemctl list-timers --all'
}
#)

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
    "Nameservers" \
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
#)

#####################################################################( services
lse_run_tests_services() {
  lse_header "srv" "services"

  ## System-V
  #check write permissions in init.d/* inetd.conf xinetd.conf
  lse_test "srv000" "0" \
    "Can we write in service files?" \
    'printf "$lse_user_writable\n" | grep -E "^/etc/(init/|init\.d/|rc\.d/|rc[0-9S]\.d/|rc\.local|inetd\.conf|xinetd\.conf|xinetd\.d/)"' \
    "fst000"

  #check write permissions for binaries involved in services
  lse_test "srv010" "0" \
    "Can we write in binaries executed by services?" \
    'for b in $(grep -ERvh "^#" /etc/inetd.conf /etc/xinetd.conf /etc/xinetd.d/ /etc/init.d/ /etc/rc* 2>/dev/null | tr -s "[[:space:]]" "\n" | grep -E "^/" | grep -Ev "^/(dev|run|sys|proc|tmp)/" | sort -u); do [ -x "$b" ] && [ -w "$b" ] && echo "$b" done'

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
    'printf "$lse_user_writable\n" | grep -E "^/(etc/systemd/|lib/systemd/).+\.service$"' \
    "fst000"

  #check write permissions for binaries involved in systemd services
  lse_test "srv510" "0" \
    "Can we write in binaries executed by systemd services?" \
    'for b in $(grep -ERh "^Exec" /etc/systemd/ /lib/systemd/ 2>/dev/null | tr "=" "\n" | tr -s "[[:space:]]" "\n" | grep -E "^/" | grep -Ev "^/(dev|run|sys|proc|tmp)/" | sort -u); do [ -x "$b" ] && [ -w "$b" ] && echo "$b" done'

  # systemd files not belonging to root
  lse_test "srv520" "1" \
    "Systemd files not belonging to root" \
    'find /lib/systemd/ /etc/systemd \! -uid 0 -type f | xargs -r ls -la'

  # systemd permissions
  lse_test "srv900" "2" \
    "Systemd config files permissions" \
    'ls -lthR /lib/systemd/ /etc/systemd/'
}
#)

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

  #check if there are credentials stored in .mysql-history
  lse_test "sof015" "0" \
    "Are there credentials in mysql_history file?" \
    'grep -Ei "(pass|identified by|md5\()" "$lse_home/.mysql_history"'

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
    'find / $lse_find_opts -name "*.htpasswd" -print -exec cat {} \;'

  #check if there are ssh private keys in ssh-agent
  lse_test "sof050" "0" \
    "Are there private keys in ssh-agent?" \
    'ssh-add -l | grep -iv "agent has no identities"'

  #check if there are gpg keys in gpg-agent
  lse_test "sof060" "0" \
    "Are there gpg keys cached in gpg-agent?" \
    'gpg-connect-agent "keyinfo --list" /bye | grep "D - - 1"'

  #check if there is a writable ssh-agent socket
  lse_test "sof070" "0" \
    "Can we write to a ssh-agent socket?" \
    'for f in $lse_user_writable; do test -S "$f" && printf "$f" | grep -Ea "ssh-[A-Za-z0-9]+/agent\.[0-9]+"; done' \
    "fst000"

  #check if there is a writable gpg-agent socket
  lse_test "sof080" "0" \
    "Can we write to a gpg-agent socket?" \
    'for f in $lse_user_writable; do test -S "$f" && printf "$f" | grep -a "gpg-agent"; done' \
    "fst000"

  #find keepass database files
  lse_test "sof090" "0" \
    "Found any keepass database files?" \
    'find / $lse_find_opts -regextype egrep -iregex ".*\.kdbx?" -readable -type f -print'

  #find pass database files
  lse_test "sof100" "0" \
    "Found any 'pass' store directories?" \
    'find / $lse_find_opts -name ".password-store" -readable -type d -print'

  #check if any tmux session is active
  lse_test "sof110" "0" \
    "Are there any tmux sessions available?" \
    'tmux list-sessions'

  #check for all tmux sessions for other users
  lse_test "sof120" "1" \
    "Are there any tmux sessions from other users?" \
    'find /tmp -type d -regex "/tmp/tmux-[0-9]+" ! -user $lse_user'

  #check if we have write access to other users tmux sessions
  lse_test "sof130" "0" \
    "Can we write to tmux session sockets from other users?" \
    'find /tmp -writable -type s -regex "/tmp/tmux-[0-9]+/.+" ! -user $lse_user -exec ls -l {} +'

  #check if there is any active screen session
  lse_test "sof140" "0" \
    "Are any screen sessions available?" \
    'screen -ls >/dev/null && screen -ls'

  #find other users screen sessions
  lse_test "sof150" "1" \
    "Are there any screen sessions from other users?" \
    'find /run/screen -type d -regex "/run/screen/S-.+" ! -user $lse_user'

  #find writable screen session sockets from other users
  lse_test "sof160" "0" \
    "Can we write to screen session sockets from other users?" \
    'find /run/screen -type s -writable -regex "/run/screen/S-.+/.+" ! -user $lse_user -exec ls -l {} +'

  #check connection to mongoDB
  lse_test "sof170" "1" \
    "Can we access MongoDB databases without credentials?" \
    'echo "show dbs" | mongo --quiet | grep -E "(admin|config|local)"'

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

  #check tmux version
  lse_test "sof540" "2" \
    "Tmux version" \
    'tmux -V'

  #check screen version
  lse_test "sof550" "2" \
    "Screen version" \
    'screen -v'

}
#)

###################################################################( containers
lse_run_tests_containers() {
  lse_header "ctn" "containers"

  #check to see if we are in a docker container
  lse_test "ctn000" "1" \
    "Are we in a docker container?" \
    'grep -i docker /proc/self/cgroup; find / $lse_find_opts -name "*dockerenv*" -exec ls -la {} \;'

  #check to see if current host is running docker services
  lse_test "ctn010" "1" \
    "Is docker available?" \
    'docker --version; docker ps -a; docker images'

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
    'groups | grep $lse_grep_opts "lxc\|lxd"'
}
#)

####################################################################( processes
lse_run_tests_processes() {
  lse_header "pro" "processes"

  #wait for the process monitor to finish gathering data
  lse_test "pro000" "2" \
    "Waiting for the process monitor to finish" \
    'while [ ! -s "$lse_procmon_data" ]; do sleep 1; done; cat "$lse_procmon_data"'\
    "" \
    "lse_procs"

  #look for the paths of the process binaries
  lse_test "pro001" "2" \
    "Retrieving process binaries" \
    'printf "%s" "$lse_procs" | cut -d" " -f5 | sort -u | xargs -r which' \
    "pro000" \
    'lse_proc_bin'

  #look for the users running the
  lse_test "pro002" "2" \
    "Retrieving process users" \
    'printf "%s" "$lse_procs" | cut -d" " -f4 | sort -u' \
    "pro000" \
    'lse_proc_users'

  #check if we have write permissions in any process binary
  lse_test "pro010" "0" \
    "Can we write in any process binary?" \
    'for b in $lse_proc_bin; do [ -w "$b" ] && echo $b; done'\
    "pro001"

  #list processes running as root
  lse_test "pro020" "1" \
    "Processes running with root permissions" \
    'printf "%s" "$lse_procs" | grep -E "^[^ ]+ [^ ]+ [^ ]+ root" | lse_proc_print' \
    "pro000"

  #list processes running as users with shell
  lse_test "pro030" "1" \
    "Processes running by non-root users with shell" \
    'for user in `printf "%s\n" "$lse_shell_users" | cut -d: -f1 | grep -v root`; do printf "%s" "$lse_proc_users" | grep -qE "(^| )$user( |\$)" && printf "\n\n------ $user ------\n\n\n" && printf "%s" "$lse_procs" | grep -E "^[^ ]+ [^ ]+ [^ ]+ $user" | lse_proc_print; done' \
    "usr030 pro000 pro002"

  #running processes
  lse_test "pro500" "2" \
    "Running processes" \
    'printf "%s\n" "$lse_procs" | lse_proc_print' \
    "pro000"

  #list running process binaries and their permissions
  lse_test "pro510" "2" \
    "Running process binaries and permissions" \
    'printf "%s\n" "$lse_proc_bin" | xargs ls -l' \
    "pro001"
}
#)

#########################################################################( CVEs
lse_run_tests_cves() {
  lse_header "cve" "CVEs"
  if [ "${#lse_cve_list}" = 1 ]; then
    echo "In order to test for CVEs, download lse.sh from the GitHub releases page."
    echo "Alternatively, build lse_cve.sh using tools/package_cvs_into_lse.sh from the repository."
  else
    for lse_cve in $lse_cve_list; do
      eval "$(printf '%s' "$lse_cve" | base64 -d | gunzip -c)"

      lse_test "$lse_cve_id" "$lse_cve_level" \
        "$lse_cve_description" \
        "lse_cve_test"
    done
  fi
}
#)
#
##)

#( Main
main() {
  while getopts "hcCil:e:p:s:S" option; do
    case "${option}" in
      c) lse_color=false; lse_grep_opts='--color=never';;
      C) lse_alt_color=true;;
      e) lse_exclude_paths "${OPTARG}";;
      i) lse_interactive=false;;
      l) lse_set_level "${OPTARG}";;
      s) lse_selection="`printf \"%s\" \"${OPTARG}\"|sed 's/,/ /g'`";;
      p) lse_proc_time="${OPTARG}";;
      S) lse_serve; exit $?;;
      h) lse_help; exit 0;;
      *) lse_help; exit 1;;
    esac
  done

  #trap to exec on SIGINT
  trap "lse_exit 1" 2

  # use alternative color scheme
  $lse_alt_color && lse_recolor

  lse_request_information
  lse_show_info
  PATH="$PATH:/sbin:/usr/sbin" #fix path just in case
  lse_distro_codename=`lse_get_distro_codename`

  lse_procmon &
  (sleep "$lse_proc_time"; rm -f "$lse_procmon_lock") &

  ## NO WAR
  lse_header "nowar" "humanity"
  lse_test "nowar0" "0" \
    'Should we question autocrats and their "military operations"?' \
    'cecho "                                    $black$b_blue  NO   $reset\n                                    $black$b_yellow  WAR  $reset"'

  lse_run_tests_users
  lse_run_tests_sudo
  lse_run_tests_filesystem
  lse_run_tests_system
  lse_run_tests_security
  lse_run_tests_recurrent_tasks
  lse_run_tests_network
  lse_run_tests_services
  lse_run_tests_software
  lse_run_tests_containers
  lse_run_tests_processes
  lse_run_tests_cves

  lse_exit 0
}

[ ! "$lse_NO_EXEC" ] && main "$@"
#)
