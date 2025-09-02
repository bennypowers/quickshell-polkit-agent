# Use Fedora which has excellent Qt6/polkit support
FROM fedora:42

# Install all dependencies including polkit Qt6
RUN dnf update -y && dnf install -y \
    qt6-qtbase-devel \
    qt6-qttools-devel \
    qt6-qtdeclarative-devel \
    polkit-qt6-1-devel \
    pkgconfig \
    python3 \
    python3-pip \
    cmake \
    gcc-c++ \
    make \
    cppcheck \
    clang-tools-extra \
    && dnf clean all

# Set up Python virtual environment
RUN python3 -m venv /opt/security-test-env && \
    /opt/security-test-env/bin/pip install --upgrade pip

# Set environment to use the virtual environment by default
ENV PATH="/opt/security-test-env/bin:$PATH"
ENV VIRTUAL_ENV="/opt/security-test-env"

WORKDIR /workspace

CMD ["bash"]