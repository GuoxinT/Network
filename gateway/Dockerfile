FROM alpine:3.20

RUN apk add --no-cache bash jq openssl openvpn iptables iproute2

WORKDIR /app
COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/*.sh

CMD ["/app/scripts/entrypoint.sh"]
