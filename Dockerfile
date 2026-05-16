
FROM rust:1.85-bullseye AS builder

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
    python3-venv \
    libffi-dev \
    libssl-dev \
    tesseract-ocr \
    ghostscript \
    imagemagick \
    curl \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /opt/ocr-venv
ENV PATH="/opt/ocr-venv/bin:${PATH}"

RUN pip install --upgrade pip --no-cache-dir && \
    pip install --upgrade setuptools wheel --no-cache-dir && \
    pip install flask --no-cache-dir && \
    pip install flask_restful --no-cache-dir && \
    pip install loguru --no-cache-dir && \
    pip install cryptography --no-cache-dir && \
    pip install pytesseract --no-cache-dir && \
    pip install Pillow --no-cache-dir && \
    pip install pyyaml --no-cache-dir
     
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
