
FROM rust:1.85-bookworm AS builder

WORKDIR /app
COPY Cargo.toml Cargo.toml
COPY Cargo.lock Cargo.lock
COPY src src

RUN cargo build --release --locked

FROM ubuntu:20.04

LABEL maintainer="tomer.klein@gmail.com"

ENV PYTHONIOENCODING=utf-8
ENV LANG=C.UTF-8
ENV DEBIAN_FRONTEND=noninteractive

RUN apt update -yqq && apt -yqq install software-properties-common
RUN add-apt-repository ppa:alex-p/tesseract-ocr-devel -y

RUN apt -yqq install python3-pip \
    libffi-dev \
    libssl-dev \
    tesseract-ocr \
    ghostscript \
    imagemagick \
    curl \
    && rm -rf /var/lib/apt/lists/*
    
RUN pip3 install --upgrade pip --no-cache-dir && \
    pip3 install --upgrade setuptools --no-cache-dir && \
    pip3 install flask --no-cache-dir && \
    pip3 install flask_restful --no-cache-dir && \
    pip3 install loguru --no-cache-dir && \
    pip3 install cryptography --no-cache-dir && \
    pip3 install pytesseract --no-cache-dir && \
    pip3 install Pillow --no-cache-dir && \
    pip3 install pyyaml --no-cache-dir
     
RUN mkdir -p /opt/ocr/tmp
RUN sed -i_bak 's/rights="none" pattern="PDF"/rights="read | write" pattern="PDF"/' /etc/ImageMagick-6/policy.xml

COPY ocr /opt/ocr

#Copy languages files
COPY traineddata /usr/share/tesseract-ocr/5/tessdata

COPY --from=builder /app/target/release/ztinfra-enclaveproducedhtml /opt/ocr/ztinfra-enclaveproducedhtml

COPY start.sh /opt/ocr/start.sh
RUN chmod +x /opt/ocr/start.sh

EXPOSE 8080
EXPOSE 5005
 
ENTRYPOINT ["/opt/ocr/start.sh"]
