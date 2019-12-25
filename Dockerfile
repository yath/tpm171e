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
