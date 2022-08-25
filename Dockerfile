FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

COPY install-pkgs.sh /install-pkgs.sh
RUN bash /install-pkgs.sh

RUN apt-get update && apt-get install -y wget cmake

ENV gvm_libs_version="v20.8.1" \
    openvas_scanner_version="v20.8.1" \
    gvmd_version="v20.8.1" \
    gsa_version="v20.8.1" \
    gvm_tools_version="21.1.0" \
    openvas_smb="v22.4.0" \
    open_scanner_protocol_daemon="v2.0.1" \
    ospd_openvas="v20.8.1" \
    python_gvm_version="v20.11.0"

RUN apt-get update && apt-get install -y  libgnutls28-dev \
                        libssh-dev \
                        libhiredis-dev \ 
                        libxml2-dev \ 
                        libgpgme-dev \ 
                        heimdal-dev \ 
                        libpopt-dev \ 
                        gcc-mingw-w64 \
                        libical-dev \
                        libpcap-dev \ 
                        libksba-dev \ 
                        bison \
                        curl \
                        libmicrohttpd-dev \
                        postgresql-14 \
                        postgresql-server-dev-14 

# Install libraries module for the GVM Libs.
RUN mkdir /build && \
    cd /build && \
    wget --no-verbose https://github.com/greenbone/gvm-libs/archive/$gvm_libs_version.tar.gz && \
    tar -zxf $gvm_libs_version.tar.gz && \
    cd /build/*/ && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make && \
    make install && \
    cd / && \
    rm -rf /build

RUN apt-get install -y libunistring-dev
# Install SMB module.
RUN mkdir /build && \
    cd /build && \
    wget --no-verbose https://github.com/greenbone/openvas-smb/archive/$openvas_smb.tar.gz && \
    tar -zxf $openvas_smb.tar.gz && \
    cd /build/*/ && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make && \
    make install && \
    cd / && \
    rm -rf /build


# Install GVMD.
RUN mkdir /build && \
    cd /build && \
    wget --no-verbose https://github.com/greenbone/gvmd/archive/$gvmd_version.tar.gz && \
    tar -zxf $gvmd_version.tar.gz && \
    cd /build/*/ && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make && \
    make install && \
    cd / && \
    rm -rf /build

 
# Install OpenVAS.
RUN mkdir /build && \
    cd /build && \
    wget --no-verbose https://github.com/greenbone/openvas-scanner/archive/$openvas_scanner_version.tar.gz && \
    tar -zxf $openvas_scanner_version.tar.gz && \
    cd /build/*/ && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make && \
    make install && \
    cd / && \
    rm -rf /build

# Install GSA.
RUN mkdir /build && \
    cd /build && \
    wget --no-verbose https://github.com/greenbone/gsa/archive/$gsa_version.tar.gz && \
    tar -zxf $gsa_version.tar.gz && \
    cd /build/*/ && \
    mkdir build && \
    cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make && \
    make install && \
    cd / && \
    rm -rf /build


# # Install OSPd daemon.
# RUN mkdir /build && \
#     cd /build && \
#     wget --no-verbose https://github.com/greenbone/ospd/archive/$open_scanner_protocol_daemon.tar.gz && \
#     tar -zxf $open_scanner_protocol_daemon.tar.gz && \
#     cd /build/*/ && \
#     python3 setup.py install && \
#     cd / && \
#     rm -rf /build


# Install Open Scanner Protocol for OpenVAS
RUN apt-get install -y python3-setuptools
RUN mkdir /build && \
    cd /build && \
    wget --no-verbose https://github.com/greenbone/ospd-openvas/archive/$ospd_openvas.tar.gz && \
    tar -zxf $ospd_openvas.tar.gz && \
    cd /build/*/ && \
    python3 setup.py install && \
    cd / && \
    rm -rf /build

COPY scripts/* /

RUN echo "/usr/local/lib" > /etc/ld.so.conf.d/openvas.conf \
    && ldconfig && cd / \
    && rm -rf /build \
    && chmod +x *.sh \
    && chmod +x sync.py


RUN apt-get install -y python3.10 \
                    python3.10-dev \
                    python3-pip \
                    && \
                    python3.10 -m pip install --upgrade pip
COPY requirement.txt /requirement.txt
RUN python3 -m pip install -r /requirement.txt
RUN /start.sh
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
CMD ["python3", "/app/agent/openvas_agent.py"]
