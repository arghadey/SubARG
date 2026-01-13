#!/bin/bash
echo "Cleaning up SubARG GUI..."
echo "Stopping Docker containers..."
docker-compose down

echo "Removing scan results..."
rm -rf app/results/*

echo "Removing Docker images..."
docker-compose rm -f

echo "Cleaning complete! Run 'docker-compose up --build' to start fresh."
