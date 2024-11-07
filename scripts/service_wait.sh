# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

#!/bin/bash

SERVICE_HOST=$1

status_code=$(curl -k -o /dev/null -s -w "%{http_code}\n" -I "https://$SERVICE_HOST")

TIMEOUT=${TIMEOUT:-60}
elapsed_time=0

echo "Waiting $TIMEOUT seconds for $SERVICE_HOST to respond..."

while [ $elapsed_time -lt $TIMEOUT ]; do

    status_code=$(curl -k -o /dev/null -s -w "%{http_code}\n" -I "https://$SERVICE_HOST" --http0.9)
    if [ $status_code -ne 000 ]; then
        break
    fi

    if curl $SERVICE_HOST --http0.9 -o /dev/null -s --max-time 3; then
        break
    fi

    sleep 1
    elapsed_time=$((elapsed_time + 1))
done

if [ $elapsed_time -ge $TIMEOUT ]; then
    echo "Timeout reached. Service did not respond."
    exit 1
fi

echo "$SERVICE_HOST is up and running."