ARG BASE_IMAGE=opensuse/leap:latest
FROM ${BASE_IMAGE} AS builder
MAINTAINER wbrown@suse.de

EXPOSE 8080

RUN mkdir /src
WORKDIR /src

ADD ./ /src/

RUN zypper in -y gcc libopenssl-devel openssl wget && \
    wget https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init && \
    chmod +x rustup-init && \
    ./rustup-init -v -y && \
    source /root/.profile && \
    cargo build --example tide --release && \
    zypper rm -y gcc libopenssl-devel && \
    rm -r rustup-init /root/.rustup

COPY --from=builder /src/target/release/examples/tide /sbin/

CMD ['/sbin/tide']


