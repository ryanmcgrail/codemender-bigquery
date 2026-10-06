# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# CodeMender Orchestrator - Universal Multi-Toolchain Base Container for GitHub Actions and Cloud Run
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install core utilities and build essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    jq \
    tar \
    gzip \
    unzip \
    psmisc \
    ca-certificates \
    build-essential \
    software-properties-common \
    gnupg \
    dirmngr \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Install Python 3.11 + 3.12 and venv support
RUN add-apt-repository ppa:deadsnakes/ppa -y && \
    apt-get update && apt-get install -y --no-install-recommends \
    python3.11 \
    python3.11-venv \
    python3.11-dev \
    python3.12 \
    python3.12-venv \
    python3.12-dev \
    python3-pip \
    python-is-python3 \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1 \
    && update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 2 \
    && update-alternatives --set python3 /usr/bin/python3.12 \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Provision pip and common test runners for Python 3.12
RUN rm -f /usr/lib/python3.12/EXTERNALLY-MANAGED && \
    python3.12 -m ensurepip --upgrade && \
    python3.12 -m pip install --no-cache-dir --upgrade pip setuptools wheel && \
    python3.12 -m pip install --no-cache-dir pytest pytest-timeout tox virtualenv

# Install Node.js 22 LTS, npm, yarn, pnpm
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    npm install -g yarn pnpm && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Install Go (latest stable)
RUN curl -fsSL https://go.dev/dl/go1.22.6.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH="/usr/local/go/bin:${PATH}"

# Install Java JDK 17, Maven, Gradle
RUN apt-get update && apt-get install -y --no-install-recommends \
    openjdk-17-jdk \
    maven \
    gradle \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

# Copy CodeMender CLI binary
COPY cm /usr/local/bin/cm
RUN chmod +x /usr/local/bin/cm

# Set up isolated /opt/codemender runtime environment
WORKDIR /opt/codemender
COPY requirements.txt .
RUN python3.12 -m venv /opt/codemender/venv && \
    /opt/codemender/venv/bin/pip install --no-cache-dir -r requirements.txt

# Copy orchestrator package and entrypoint script
COPY codemender_agent ./codemender_agent
COPY orchestrator.py .

ENV PYTHONPATH=/opt/codemender

RUN mkdir -p /workspace

# Set entrypoint to isolated virtual environment python
ENTRYPOINT ["/opt/codemender/venv/bin/python3", "/opt/codemender/orchestrator.py"]
