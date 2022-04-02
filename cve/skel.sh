#!/bin/posh
# shellcheck disable=1003,1091,2006,2016,2034,2039
# vim: set ts=2 sw=2 sts=2 fdm=marker fmr=#(,#) et:
#
# doc:
#
#  Copy this file to a new one with the same name of the cve to test, all in
# lowercase (i.e.: cve-2014–6271.sh).
#  Then add the code for the functions shown here. **ALL** functions must appear
# in the new created file, however the ones marked as 'optional' can be left
# with the same code than in 'skel.sh'. Inside the function, declare all the
# variables as 'local' (i.e.: local vuln_version="1.2.3")
#
#  NOTE: You can use here, functions and variables implemented in 'lse.sh':
#   * lse_get_pkg_version: Get package version supplying package name
#   * lse_is_version_bigger: Check if version in $1 is bigger than the $2
#   * $lse_arch: System architecture
#   * $lse_distro_codename: The linux distribution code name (ubuntu, debian,
#      opsuse, centos, redhat, fedora)
#   * $lse_linux: Kernel version
#   * Colors
#  XXX: Check the definitions in 'lse.sh' to better understand what they do and
#       how they work
#
################################################################################
## RULES:
##  * Do NOT cause any harm with the tests
##  * Try to be as accurate as possible, trying to detect patched versions from
##    distro package versions. Try to minimize false positives.
##  * The script must be POSIX compliant. Test it with 'posh' shell.
################################################################################


# lse_cve_level: 0 if leads to a privilege escalation; 1 for other CVEs
lse_cve_level=0

# lse_cve_id: CVE id in lowercase (i.e.: cve-2014–6271)
lse_cve_id="cve-2014–6271"

# lse_cve_description: Short. Not more than 52 characters long.
#__________________="vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
lse_cve_description="This is a short description about the vulnerability."

# Code retrieved with 'declare -f' by the packaging bash script
lse_cve_test() { #(
  # Checks if the software is installed and the version matches a vulnerable one
  # If it is vulnerable it must show something via stdout.
  # NOTE: Take care that this function does not output anything to stdout or
  #       stderr other than information that you want to be visible ONLY WHEN IT
  #       IS VULNERABLE. If it is not vulnerable there should NOT BE ANY OUTPUT.
  echo "Vulnerable!"
} #)

# Uncomment this line for testing the lse_cve_test function
#lse_NO_EXEC=true . ../lse.sh ; lse_cve_test
