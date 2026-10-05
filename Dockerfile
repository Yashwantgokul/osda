FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y \
        bash \
        curl \
        wget \
        procps \
        iproute2 \
        iputils-ping \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /workspace
