# Multi-stage Dockerfile for MXD Library
FROM ubuntu:22.04 AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    pkg-config \
    libssl-dev \
    libsodium-dev \
    librocksdb-dev \
    libcjson-dev \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for building
RUN useradd -m -u 1000 builder
USER builder
WORKDIR /home/builder

# Copy source code
COPY --chown=builder:builder . /home/builder/mxdlib/

# Build the library
WORKDIR /home/builder/mxdlib
RUN ./install_dependencies.sh && \
    mkdir -p build && \
    cd build && \
    cmake .. && \
    make -j$(nproc)

# Production stage
FROM ubuntu:22.04

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    libssl3 \
    libsodium23 \
    librocksdb6.11 \
    libcjson1 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for runtime
RUN useradd -m -u 1001 mxdnode && \
    mkdir -p /opt/mxd/data /opt/mxd/config /opt/mxd/logs && \
    chown -R mxdnode:mxdnode /opt/mxd

# Copy built binaries and libraries
COPY --from=builder --chown=mxdnode:mxdnode /home/builder/mxdlib/build/libmxd.so /opt/mxd/lib/
COPY --from=builder --chown=mxdnode:mxdnode /home/builder/mxdlib/build/mxd_node /opt/mxd/bin/
COPY --from=builder --chown=mxdnode:mxdnode /home/builder/mxdlib/src/node/default_config.json /opt/mxd/config/

# Set up environment
USER mxdnode
WORKDIR /opt/mxd
ENV PATH="/opt/mxd/bin:$PATH"
ENV LD_LIBRARY_PATH="/opt/mxd/lib:$LD_LIBRARY_PATH"

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Expose ports
EXPOSE 8000 8080

# Default command
CMD ["mxd_node", "--config", "/opt/mxd/config/default_config.json", "--data-dir", "/opt/mxd/data"]
