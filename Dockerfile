FROM golang:latest

LABEL maintainer="Justin Azoff <justin.azoff@gmail.com>" \
      org.opencontainers.image.title="ssh-auth-logger" \
      org.opencontainers.image.description="A low/zero interaction ssh authentication logging honeypot" \
      org.opencontainers.image.source="https://github.com/JustinAzoff/ssh-auth-logger" \
      org.opencontainers.image.url="https://hub.docker.com/r/justinazoff/ssh-auth-logger" \
      org.opencontainers.image.documentation="https://github.com/JustinAzoff/ssh-auth-logger#" \
      org.opencontainers.image.version="0.1.0"

ENV USER=nobody
ENV SSHD_BIND=:2222

RUN go install github.com/JustinAzoff/ssh-auth-logger@latest && \
    touch /var/log/ssh-auth-logger.log && \
    chown nobody /var/log/ssh-auth-logger.log && \ 
    chmod 644 /var/log/ssh-auth-logger.log

USER $USER

EXPOSE 2222

CMD /go/bin/ssh-auth-logger 2>&1 | tee -a /var/log/ssh-auth-logger.log