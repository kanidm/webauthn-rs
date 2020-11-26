FROM opensuse/leap:latest
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
    cargo build --example actix --release && \
    zypper rm -y gcc libopenssl-devel && \
    rm -r rustup-init /root/.rustup

CMD ['/src/target/release/examples/actix']


