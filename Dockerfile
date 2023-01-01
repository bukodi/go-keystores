# Based on https://github.com/psmiraglia/docker-softhsm
# Copyright 2018 Paolo Smiraglia <paolo.smiraglia@gmail.com>

FROM ubuntu:20.04 AS go-keystores-dev

ARG SOFTHSM2_VERSION=2.6.1
ARG GO_VERSION=1.19.4

ENV SOFTHSM2_VERSION=${SOFTHSM2_VERSION} \
    SOFTHSM2_SOURCES=/tmp/softhsm2
ENV GO_VERSION=${GO_VERSION}

# install build dependencies
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata

RUN apt-get install -y wget git gcc libp11-kit-dev \
    cmake automake autoconf libtool \
    libpcsclite-dev pcscd pcsc-tools opensc \
    libssl-dev build-essential

# Install golang
RUN wget -P /tmp "https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz"

RUN tar -C /usr/local -xzf "/tmp/go${GO_VERSION}.linux-amd64.tar.gz"
RUN rm "/tmp/go${GO_VERSION}.linux-amd64.tar.gz"

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

# build and install SoftHSM2
RUN git clone https://github.com/opendnssec/SoftHSMv2.git ${SOFTHSM2_SOURCES}
WORKDIR ${SOFTHSM2_SOURCES}

RUN git checkout ${SOFTHSM2_VERSION} -b ${SOFTHSM2_VERSION} \
    && sh autogen.sh \
    && ./configure \
    && make \
    && make install

WORKDIR /root
RUN rm -fr ${SOFTHSM2_SOURCES}

