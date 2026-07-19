FROM --platform=linux/amd64 ubuntu@sha256:52df9b1ee71626e0088f7d400d5c6b5f7bb916f8f0c82b474289a4ece6cf3faf

ENV CC=clang-18 \
    CXX=clang++-18 \
    LD=ld.lld-18 \
    LLVM_CONFIG=llvm-config-18 \
    AFL_PATH=/usr/local/lib/afl

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang-18 \
        cmake \
        curl \
        default-jre-headless \
        git \
        libclang-18-dev \
        libclang-rt-18-dev \
        libfuzzer-18-dev \
        lld-18 \
        llvm-18 \
        llvm-18-dev \
        llvm-18-tools \
        make \
        ninja-build \
        python3 \
        python3-dev \
        unzip \
        uuid-dev \
        wget \
        zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

ARG AFL_VERSION=v4.40c
ARG AFL_COMMIT=e5a8ba39ecf97d05e286fdd4e01da96554dbf64f
ARG GRAMMAR_MUTATOR_COMMIT=0a0da05305466bfe0b27bbb7cf24a7ddf8a66811
ARG ANTLR_SHA256=73a49d6810d903aa4827ee32126937b85d3bebec0a8e679b0dd963cbcc49ba5a

RUN run_with_heartbeat() { \
        "$@" & build_pid=$!; \
        while kill -0 "${build_pid}" 2>/dev/null; do \
            echo "BigEye toolchain build is active"; \
            sleep 15; \
        done; \
        wait "${build_pid}"; \
    }; \
    git clone --depth 1 --branch "${AFL_VERSION}" \
        https://github.com/AFLplusplus/AFLplusplus.git /tmp/AFLplusplus \
    && test "$(git -C /tmp/AFLplusplus rev-parse HEAD)" = "${AFL_COMMIT}" \
    && git -C /tmp/AFLplusplus submodule update --init --depth 1 \
        custom_mutators/grammar_mutator/grammar_mutator \
    && test "$(git -C /tmp/AFLplusplus/custom_mutators/grammar_mutator/grammar_mutator rev-parse HEAD)" = "${GRAMMAR_MUTATOR_COMMIT}" \
    && run_with_heartbeat make -C /tmp/AFLplusplus -j "$(nproc)" \
        LLVM_CONFIG=llvm-config-18 CC=clang-18 CXX=clang++-18 all \
    && run_with_heartbeat make -C /tmp/AFLplusplus \
        LLVM_CONFIG=llvm-config-18 CC=clang-18 CXX=clang++-18 install \
    && curl -fsSL https://www.antlr.org/download/antlr-4.8-complete.jar \
        -o /tmp/antlr-4.8-complete.jar \
    && echo "${ANTLR_SHA256}  /tmp/antlr-4.8-complete.jar" | sha256sum -c - \
    && run_with_heartbeat make -C /tmp/AFLplusplus/custom_mutators/grammar_mutator/grammar_mutator \
        -j "$(nproc)" ENABLE_TESTING= \
        GRAMMAR_FILE=grammars/json.json \
        ANTLR_JAR_LOCATION=/tmp/antlr-4.8-complete.jar \
    && install -m 0755 \
        /tmp/AFLplusplus/custom_mutators/grammar_mutator/grammar_mutator/src/libgrammarmutator-json.so \
        /usr/local/lib/afl/libgrammarmutator-json.so \
    && install -m 0755 \
        /tmp/AFLplusplus/custom_mutators/grammar_mutator/grammar_mutator/src/grammar_generator-json \
        /usr/local/bin/grammar_generator-json \
    && test "$(afl-fuzz --version)" = "afl-fuzz++4.40c" \
    && test -x /usr/local/bin/afl-clang-fast \
    && test -x /usr/local/bin/afl-cmin \
    && test -x /usr/local/bin/afl-tmin \
    && test -x /usr/local/bin/afl-showmap \
    && test -s /usr/local/lib/afl/libgrammarmutator-json.so \
    && rm -rf /tmp/AFLplusplus /tmp/antlr-4.8-complete.jar /root/.cache

ENV LD_LIBRARY_PATH=/usr/local/lib/afl
