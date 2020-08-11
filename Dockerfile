FROM ubuntu:20.04
ARG binary
RUN ln -fs /usr/share/zoneinfo/Asia/Ho_Chi_Minh /etc/localtime
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y    libpcap0.8-dev libxml2-dev libvirt-dev
COPY $binary /root/

