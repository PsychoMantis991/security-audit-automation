#!/bin/bash

# Start the reporting service (a simple HTTP server)
cd /opt/reporting
python3 -m http.server 8000