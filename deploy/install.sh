#!/bin/bash
# Prepare directories only; stop the service before rerunning.
set -euo pipefail
umask 077
config_dir=/etc/mariadb-mcp
state_dir=/var/lib/mariadb-mcp

fail(){ printf 'Error: %s\n' "$1" >&2; return 1; }
normalize_directory(){
 python3 - "$1" <<'NORMALIZE'
import os, pathlib, sys
raw=pathlib.Path(sys.argv[1])
if not raw.is_absolute(): raw=pathlib.Path.cwd()/raw
path=pathlib.Path(raw.anchor)
for part in raw.parts[1:]:
 candidate=path/part
 if candidate.is_symlink(): sys.exit("Unsafe symlink in directory path")
 path=path.parent if part==".." else candidate
if path==pathlib.Path(path.anchor): sys.exit("Filesystem root is not an application directory")
print(path)
NORMALIZE
}
validate_tree(){
 local path=$1 unsafe
 [[ ! -e $path || -d $path ]] || fail 'A directory path is occupied by another file type.'
 if [[ -d $path ]]; then
  unsafe=$(find -P "$path" \( ! -type d ! -type f -o -type f -links +1 \) -print -quit)
  [[ -z $unsafe ]] || fail 'Inspect symlinks, special files or hard links before changing permissions.'
 fi
}
prepare_directories(){
 [[ $(id -u) == 0 ]] || fail 'Run this helper with sudo on the automation box.'
 local uid gid group_name group_password group_gid path entry
 config_dir=$(normalize_directory "$config_dir")
 state_dir=$(normalize_directory "$state_dir")
 [[ $config_dir != "$state_dir" && $config_dir != "$state_dir/"* && $state_dir != "$config_dir/"* ]] || fail 'Configuration and state must be separate directories.'
 for path in "$config_dir" "$state_dir"; do validate_tree "$path"; done
 if ! id -u mcpagent >/dev/null 2>&1; then
  useradd --system --user-group --home-dir "$state_dir" --no-create-home --shell /usr/sbin/nologin mcpagent
 fi
 uid=$(id -u mcpagent);gid=$(id -g mcpagent)
 IFS=: read -r group_name group_password group_gid < <(getent group mcpagent)
 [[ $uid != 0 && $gid != 0 && $group_gid == "$gid" ]] || fail 'mcpagent must be unprivileged with primary group mcpagent.'
 mkdir -p -- "$config_dir/apps.d" "$config_dir/connections" "$config_dir/credentials" "$state_dir"
 for path in "$config_dir" "$state_dir"; do
  while IFS= read -r -d '' entry; do
   chown --no-dereference mcpagent:mcpagent -- "$entry"
   if [[ -d $entry ]]; then chmod 700 -- "$entry"; else chmod 600 -- "$entry"; fi
  done < <(find -P "$path" -print0)
 done
 printf 'MariaDB MCP directories and existing files now have private mcpagent permissions.\n'
}
if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
 if [[ $# == 1 && $1 == --help ]]; then
  printf 'Usage: sudo bash install.sh\nCreates MCP directories and fixes ownership/permissions; preserves files and tokens.\nStop mariadb-mcp before running; rerun after copying configuration.\nRequires Python 3 and standard Linux account utilities. Does not deploy or start services.\n'
 elif [[ $# != 0 ]]; then fail 'Only --help is accepted.'
 else prepare_directories
 fi
fi
