# Use a lightweight Python base image
FROM python:3.11-alpine

# Install CA certificates
RUN apk add --no-cache ca-certificates

# Set the working directory
WORKDIR /app

# Copy application files into the container
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Default command to run the application
CMD ["python", "main.py"]
