FROM schoolvpn-network:local
WORKDIR /app
COPY scripts/ /app/scripts/
RUN chmod +x /app/scripts/*.sh /app/scripts/*.py
CMD ["/app/scripts/private_socks.py"]
