FROM python:3.12-slim

WORKDIR /app

# Install uv
RUN pip install uv

# Copy project files
COPY pyproject.toml uv.lock* README.md ./
COPY src/ src/
COPY dashboard/ dashboard/
COPY scripts/ scripts/
COPY docs/ docs/
COPY data/keys/.gitkeep data/keys/.gitkeep

# Install dependencies
RUN uv sync --no-dev

# Create data directories
RUN mkdir -p data/runs/envelopes data/runs/policy_compares data/runs/envelope_compares \
    data/index data/bundles data/review data/keys

# Expose ports
EXPOSE 8001 8506

# Start script will be the entrypoint
COPY deploy/start.sh /app/start.sh
RUN chmod +x /app/start.sh

CMD ["/app/start.sh"]
