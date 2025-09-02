# Use Ubuntu 24.04 which has libpolkit-qt6-1-dev available
FROM ubuntu:24.04

# Install all dependencies including polkit Qt6
RUN apt-get update && apt-get install -y \
    qt6-base-dev \
    qt6-tools-dev \
    libqt6core6 \
    libqt6network6 \
    qt6-declarative-dev \
    pkg-config \
    python3 \
    python3-pip \
    python3-venv \
    cmake \
    build-essential \
    libpolkit-qt6-1-dev \
    cppcheck \
    clang-tidy \
    && rm -rf /var/lib/apt/lists/*

# Set up Python virtual environment
RUN python3 -m venv /opt/security-test-env && \
    /opt/security-test-env/bin/pip install --upgrade pip

# Set environment to use the virtual environment by default
ENV PATH="/opt/security-test-env/bin:$PATH"
ENV VIRTUAL_ENV="/opt/security-test-env"

WORKDIR /workspace

CMD ["bash"]