# Managed by f2b-toolkit. Use configure / plan / apply to update.
# UFW bans the source across ports; the port setting does not restrict this action.
[sshd]
enabled = true
filter = sshd[mode=normal]
backend = $backend
$log_source
port = $ports
usedns = no
ignoreself = true
ignoreip = $trusted_ips
bantime = $bantime
findtime = $findtime
maxretry = $maxretry
bantime.increment = false
action = ufw
