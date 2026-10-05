#!/bin/bash

echo "Starting suspicious behaviour..."

bash -c 'sleep 1 & curl -s http://example.com > /dev/null & wait'
