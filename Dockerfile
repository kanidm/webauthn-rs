FROM opensuse/tumbleweed:latest AS ref_repo

#	sed -i -E 's/https?:\/\/download.opensuse.org/http:\/\/dl.suse.blackhats.net.au:8080/g' /etc/zypp/repos.d/*.repo && \

RUN zypper ar obs://devel:languages:rust devel:languages:rust && \
	sed -i -E 's/https?:\/\/download.opensuse.org/https:\/\/mirror.firstyear.id.au/g' /etc/zypp/repos.d/*.repo && \
	zypper --gpg-auto-import-keys ref --force

# // setup the builder pkgs
FROM ref_repo AS build_base
RUN zypper install -y cargo rust gcc libopenssl-devel

# // setup the runner pkgs
FROM ref_repo AS run_base
RUN zypper install -y openssl timezone

# // build artifacts
FROM build_base AS builder

COPY . /home/webauthn-rs/
RUN mkdir /home/webauthn-rs/.cargo
WORKDIR /home/webauthn-rs/compat_tester/webauthn-rs-demo/

# RUN cp cargo_vendor.config .cargo/config
RUN cargo build --release

# == end builder setup, we now have static artifacts.
FROM run_base
MAINTAINER william@blackhats.net.au
EXPOSE 8080
WORKDIR /

RUN cd /etc && \
    ln -sf ../usr/share/zoneinfo/Australia/Brisbane localtime

COPY --from=builder /home/webauthn-rs/target/release/webauthn-rs-demo /bin/
COPY --from=builder /home/webauthn-rs/compat_tester/webauthn-rs-demo/pkg /pkg

ENV RUST_BACKTRACE 1
CMD ["/bin/webauthn-rs-demo"]
