FROM opensuse/leap:latest
MAINTAINER wbrown@suse.de

EXPOSE 8080

RUN mkdir /src
WORKDIR /src

ADD ./ /src/

RUN zypper in -y cargo rust rust-std gcc libopenssl-devel openssl && \
    cargo build --example actix --release && \
    zypper rm -y cargo rust rust-std gcc libopenssl-devel

CMD ['/src/target/release/examples/actix']


