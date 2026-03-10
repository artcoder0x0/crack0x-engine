#!/bin/sh
nginx -g "daemon off;" &
cd /app && node admin-server.js