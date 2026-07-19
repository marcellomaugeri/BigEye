FROM --platform=linux/amd64 ubuntu:24.04

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        ca-certificates \
        clang-18 \
        cmake \
        git \
        libclang-rt-18-dev \
        libfuzzer-18-dev \
        lld-18 \
        llvm-18 \
        make \
        ninja-build \
    && rm -rf /var/lib/apt/lists/*

ENV CC=clang-18 \
    CXX=clang++-18 \
    LD=ld.lld-18
