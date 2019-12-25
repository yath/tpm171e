# 1) Build Docker Image: docker build --tag tpm171e .
# 2) Make all: run --rm -it -v="$(pwd):/code" tpm171e
# 3) Custom build: docker run --rm -it -v="$(pwd):/code" tpm171e bash

FROM ubuntu:18.04

ENV DEBIAN_FRONTEND noninteractive
ENV SERVERNUM 1

RUN mkdir /code
WORKDIR /code

RUN apt update && apt install -y apt-utils \
					build-essential \
					net-tools \
					cmake \
					git \
					nano \
					gdb \
					strace \
          android-tools-adb \
          android-tools-fastboot \
          gcc-arm-none-eabi \
          binutils-arm-none-eabi \
          golang \
          go-bindata \
          xxd

CMD make
