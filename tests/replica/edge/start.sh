#!/bin/sh
# Start the edge Postfix with the replica settings. MODE=before uses the pre-Tidegate main.cf.
set -eu
id ross >/dev/null 2>&1 || useradd -m -s /bin/sh ross
cp /edge/virtual /edge/tidegate_filter /edge/tidegate_return.cidr /etc/postfix/
if [ "${MODE:-tidegate}" = before ]; then cp /edge/main.cf.before /etc/postfix/main.cf; else cp /edge/main.cf /etc/postfix/main.cf; fi
grep -q '^tidegate ' /etc/postfix/master.cf || cat /edge/master-tidegate.cf >> /etc/postfix/master.cf
sed -i -E 's/^(smtp +inet +n +- +)y/\1n/; s/^([a-z]+ +unix +[-n] +- +)y/\1n/' /etc/postfix/master.cf
rm -f /var/spool/postfix/pid/master.pid
python3 /edge/forward.py &
postfix check
exec postfix start-fg
