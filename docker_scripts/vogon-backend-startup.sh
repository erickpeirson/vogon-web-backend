#!/bin/bash
source /usr/src/app/data/env_secrets
service redis-server start
service supervisor start
cd /usr/src/app/vogon-web
python manage.py createcachetable
python manage.py migrate
python manage.py test
if [ "$?" = "0" ]; then
    printf "[TEST] - executable built: ${EXEC}\n"
else
    printf "[TEST] - failed\n"
    exit 1
fi
tail -f /dev/null

if python manage.py test; then
else return exit 1 fi
