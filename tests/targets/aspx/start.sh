#!/bin/bash
fastcgi-mono-server4 /applications=/:/app /socket=tcp:127.0.0.1:9000 &
sleep 1
nginx -g 'daemon off;'
