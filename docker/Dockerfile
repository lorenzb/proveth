FROM ubuntu:bionic

# House keeping
RUN apt-get update 

# Python 3.6 and pip dependencies
RUN apt-get -y install apt-utils python3.6 python3.6-dev python3-pip git gcc && apt-get -y install pkg-config libffi6 autoconf automake libtool openssl libssl-dev

# Solidity
RUN apt-get -y install software-properties-common && add-apt-repository -y ppa:ethereum/ethereum && apt-get update && apt-get -y install solc

