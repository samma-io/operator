#!/bin/bash
echo "starting up the webserver"
gunicorn -b 0.0.0.0:80 \
        --access-logfile - \
        --access-logformat  "{'remote_ip':'%(h)s','request_id':'%({X-Request-Id}i)s','response_code':'%(s)s','request_method':'%(m)s','request_path':'%(U)s','request_querystring':'%(q)s','request_timetaken':'%(D)s','response_length':'%(B)s'}" \
        -w 1 app:app