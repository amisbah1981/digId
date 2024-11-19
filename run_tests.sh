#!/bin/bash

# Run pytest with verbose mode
pytest -v -s .

# Generate a coverage report
pytest --cov=. --cov-report=term-missing > coverage_report.txt

# Output the coverage report for visibility
cat coverage_report.txt
