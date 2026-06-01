FROM alpine:3.20

RUN apk add --no-cache bash python3 shadowsocks-rust-ssserver

WORKDIR /app
COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/*.sh

CMD ["/app/scripts/entrypoint.sh"]
