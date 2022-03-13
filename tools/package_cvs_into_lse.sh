#!/bin/bash
# vim: set ts=2 sw=2 sts=2 et:

#( options
new_lse="lse_cve.sh"
lse_cve_list_marker='#CVElistMARKER'
#)

#( lib
do_check() {
  [ -d "./cve" ] && [ -f "./lse.sh" ] && return 0
  echo "Error: Run this script from the main repository directory"
  exit 1
}
do_strip_script() {
  local script_path="$1"
  env "BASH_FUNC_tmp_%%=() {
    $(<$script_path)
  }" bash --posix -c 'declare -f tmp_' | tail -n+3 | head -n -1 | sed 's/^[[:space:]]\+\(.*\)/\1/g'
}
#)

#( main
do_check

[ -f "$new_lse" ] && rm -f "$new_lse"
cp "lse.sh" "$new_lse"

for f in cve/cve-*.sh; do
  cve_code=$(do_strip_script "$f" | gzip -c | base64 -w0)
  sed -i "s|.*${lse_cve_list_marker}.*|${cve_code}\n\" ${lse_cve_list_marker}|g" "$new_lse"
done
#)

