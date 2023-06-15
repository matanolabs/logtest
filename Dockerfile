FROM python:3.11-bullseye AS builder
WORKDIR /logtest
RUN apt-get update && apt-get install wget tar -y && \
    wget https://github.com/Wilfred/difftastic/releases/download/0.47.0/difft-x86_64-unknown-linux-gnu.tar.gz && \
    tar -xf difft-x86_64-unknown-linux-gnu.tar.gz && \
    rm difft-x86_64-unknown-linux-gnu.tar.gz && mv difft /usr/bin/
COPY . /logtest/
RUN pip3 install -r requirements.txt --target . && \
    rm requirements.txt
# Removing python intermediate bytecodes
RUN find . -regex '^.*\(__pycache__\|\.py[co]\)$' -delete


FROM cgr.dev/chainguard/python:latest
USER 0
WORKDIR /logtest
COPY --from=builder /logtest /logtest
COPY --from=builder /usr/bin/difft /usr/bin/difft
ENTRYPOINT  ["python3", "-u", "main.py" ]
