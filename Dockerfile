# Use a minimal Python base image
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Copy the script into the container
COPY gal_extractor.py .

# Install required dependencies
RUN pip install --no-cache-dir requests urllib3

# Set default command
ENTRYPOINT ["python", "emailextract.py"]
