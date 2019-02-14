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

#dump user groups
[ $lse_level -ge 2 ] && lse_test "usr040" "2" "Groups for other users" "`cat /etc/group 2>/dev/null`"

#dump users
[ $lse_level -ge 2 ] && lse_test "usr050" "2" "Other users" "`cat /etc/passwd 2>/dev/null`"


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
lse_user_writable="`find / -writable -not -path "$HOME/*" 2>/dev/null`"
lse_test "fs000" "1" "Writable files outside users home" "$lse_user_writable"

#get setuid binaries
lse_setuid_binaries="`find / -perm -4000 2> /dev/null`"
lse_test "fs010" "1" "Binaries with setuid bit" "$lse_setuid_binaries"

#uncommon setuid binaries
lse_test_passed "fs010" && \
  lse_test "fs020" "0" "Uncommon setuid binaries" "`echo -e "$lse_setuid_binaries" | grep -Ev '^/(bin|sbin|usr/bin|usr/lib|usr/sbin)' 2>/dev/null`"
  
#can we read /root
lse_test "fs030" "1" "Can we read /root?" "`ls -ahl /root/ 2>/dev/null`"

#check /home permissions
lse_test "fs040" "1" "Can we read subdirectories under /home?" "`for h in /home/*; do [ -d "$h" ] && [ "$h" != "$lse_home" ] && ls -la "$h/"; done  2>/dev/null`"

#check for SSH files in home directories
lse_test "fs050" "1" "SSH files in home directories" "`for h in $(cut -d: -f6 /etc/passwd); do find "$h" \( -name "*id_dsa*" -o -name "*id_rsa*" -o -name "known_hosts" -o -name "authorized_hosts" -o -name "authorized_keys" \) -exec ls -la {} 2>/dev/null \; ; done 2>/dev/null`"

#files owned by user
[ $lse_level -ge 2 ] && lse_test "fs060" "2" "Files owned by $lse_user" "`find / -user $lse_user -type f ! -path "/proc/*" ! -path "/sys/*" -exec ls -al {} \; 2>/dev/null`"


#######################################################################( system
lse_header "system"

#who is logged in
[ $lse_level -ge 2 ] && lse_test "sys000" "2" "Who is logged in" "`w 2>/dev/null`"

#last logged in users
[ $lse_level -ge 2 ] && lse_test "sys010" "2" "Last logged in users" "`last 2>/dev/null`"

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

#
##)
