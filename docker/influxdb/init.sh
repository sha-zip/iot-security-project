#!/bin/bash
# InfluxDB initialization script
# This script runs after InfluxDB starts to set up the bucket and organization

echo "InfluxDB initialization complete."
echo "Organization: ${DOCKER_INFLUXDB_INIT_ORG}"
echo "Bucket: ${DOCKER_INFLUXDB_INIT_BUCKET}"
echo "InfluxDB is ready to receive data."
