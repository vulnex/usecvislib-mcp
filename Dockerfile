ARG BASE_IMAGE=usecvislib-usecvislib-api:latest
FROM ${BASE_IMAGE}

USER root

# Copy MCP package
COPY . /app/usecvislib-mcp/

# Install MCP package (production only, no dev extras)
RUN pip install --no-cache-dir /app/usecvislib-mcp

# Fix ownership
RUN chown -R appuser:appuser /app/usecvislib-mcp

USER appuser

# Default to streamable-http transport for Docker
ENV USECVISLIB_MCP_TRANSPORT=streamable-http
ENV USECVISLIB_MCP_HOST=0.0.0.0
ENV USECVISLIB_MCP_PORT=8000
# API key is required for HTTP transport. Set at runtime:
#   docker run -e USECVISLIB_MCP_API_KEY=your-secret-key ...
# To run without auth (NOT recommended): -e USECVISLIB_MCP_ALLOW_NO_AUTH=true

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=10s \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"

CMD ["usecvislib-mcp"]
