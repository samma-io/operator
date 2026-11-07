#!/bin/bash
echo "starting up the webserver"
# Every address of both families where the kernel has IPv6: a pod's address
# is IPv6 on an IPv6-first cluster, and a 0.0.0.0 listener refuses it. "[::]"
# also takes IPv4 (as IPv4-mapped addresses) while net.ipv6.bindv6only is 0,
# the Linux default.
if [ -e /proc/net/if_inet6 ]; then
        BIND="[::]:8080"
else
        BIND="0.0.0.0:8080"
fi
gunicorn -b "$BIND" \
        --access-logfile - \
        --access-logformat  "{'remote_ip':'%(h)s','request_id':'%({X-Request-Id}i)s','response_code':'%(s)s','request_method':'%(m)s','request_path':'%(U)s','request_querystring':'%(q)s','request_timetaken':'%(D)s','response_length':'%(B)s'}" \
        -w 1 app:app