FROM python:3.9-slim

# Install system dependencies including Go
RUN apt-get update && apt-get install -y \
    wget \
    git \
    python3-pip \
    jq \
    dnsutils \
    golang \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create necessary directories
RUN mkdir -p /app/app/results /app/app/static /app/app/templates /root/tools /root/tools/wordlists

# Install Go tools (including httprobe)
RUN go install github.com/tomnomnom/httprobe@latest && \
    ln -s /root/go/bin/httprobe /usr/local/bin/

# Install Python tools
RUN pip install sublist3r

# Download wordlist
RUN wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt \
    -O /root/tools/wordlists/subdomains.txt || \
    echo "www" > /root/tools/wordlists/subdomains.txt

# Expose port
EXPOSE 5000

# Run application
CMD ["python", "run.py"]
