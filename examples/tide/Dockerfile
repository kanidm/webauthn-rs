ARG BASE_IMAGE=opensuse/leap:latest
FROM ${BASE_IMAGE} AS builder
LABEL maintainer wbrown@suse.de

RUN mkdir /src
WORKDIR /src

ADD ./ /src/

RUN zypper in -y gcc libopenssl-devel openssl wget && \
    wget https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init && \
    chmod +x rustup-init && \
    ./rustup-init -v -y && \
    source /root/.profile && \
    cargo build --example tide --release

FROM ${BASE_IMAGE}
LABEL maintainer wbrown@suse.de


RUN zypper ref && \
    zypper install -y \
        timezone && \
    zypper clean -a

COPY --from=builder /src/target/release/examples/tide /sbin/
COPY --from=builder /src/static /static

EXPOSE 8080

CMD ["/sbin/tide", "-d"]


