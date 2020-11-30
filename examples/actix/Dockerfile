FROM rust:1.48.0 as builder
WORKDIR /src
COPY . .
RUN cargo build --example actix --release

FROM debian:buster-slim
RUN apt-get update && apt-get install -y openssl && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY examples/actix/.env /app/.env
COPY static /app/static/
COPY templates /app/templates/
COPY --from=builder /src/target/release/examples/actix /app/actix
EXPOSE 8080
CMD ["/app/actix"]
