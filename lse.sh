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
  cecho "${grey}---"
  if $lse_interactive; then
    [ -z "$lse_user" ] && lse_user=`lse_ask "Could not find current user name. Current user?"`
    lse_pass=`lse_ask "If you know the current user password, write it here for better results"`
  fi
  cecho "${grey}---"
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
  [ $level -eq 1 ] && l="${lyellow}*"
  [ $level -eq 2 ] && l="${lblue}i"

  cecho -n "${white}[${l}${white}] $name${grey}"
  for i in $(seq $((${#name}+4)) 74); do
    echo -n "."
  done

  if [ -z "$output" ]; then
    cecho "${red} nope${reset}"
  else
    lse_passed_tests+=" $id"
    cecho "${lgreen} yes!${reset}"
    if [ $lse_level -ge $level ]; then
      cecho "${grey}---$reset"
      echo "$output"
      cecho "${grey}---$reset\n"
    fi
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

########################################################################( tests
#
#  A successful test will receive some output while a failed tests will receive
# an empty string.
#
# Example of a test
lse_user_writable="$( find / -writable -not -path "$HOME/*" 2>/dev/null )"
lse_test "000" "1" "Writable files outside users home" "$lse_user_writable"

#
##)
