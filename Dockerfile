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

WORKDIR /app

COPY . .

RUN go install . && \
    touch /var/log/ssh-auth-logger.log && \
    chown $USER /var/log/ssh-auth-logger.log && \
    chmod 644 /var/log/ssh-auth-logger.log

USER $USER

EXPOSE 2222

CMD test -f /var/log/ssh-auth-logger.log || { echo 'Creating log file...' && touch /var/log/ssh-auth-logger.log ; }; /go/bin/ssh-auth-logger 2>&1 | tee -a /var/log/ssh-auth-logger.log