# Use a lightweight Python base image
FROM python:3.11-alpine

# Set the working directory
WORKDIR /app

# Install CA certificates for SSL verification
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates

# Copy application files into the container
COPY . /app

# Install Python dependencies from requirements.txt
RUN pip install --no-cache-dir --trusted-host pypi.org --trusted-host files.pythonhosted.org -r requirements.txt

# Default command to run your script
CMD ["bash", "/app/run_tests.sh"]
