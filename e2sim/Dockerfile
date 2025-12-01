FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV E2SIM_DIR=/home/e2sim

RUN apt-get update \
 && apt-get install -y \
    build-essential \
    git \
    cmake \
    pkg-config \
    curl \
    libsctp-dev \
    lksctp-tools \
    autoconf \
    automake \
    libtool \
    bison \
    flex \
    libboost-all-dev \
    iputils-ping \
    net-tools \
    nano \
    vim \
    tcpdump \
    nmap \
    libcurl4-openssl-dev \
    libyaml-cpp-dev \
    nlohmann-json3-dev \
	gdb \
 && rm -rf /var/lib/apt/lists/*

# Copia il codice (usa la tua build context)
COPY . ${E2SIM_DIR}

WORKDIR ${E2SIM_DIR}
RUN mkdir config

# Build
RUN ./build_e2sim --clean && ./build_e2sim
