FROM golang:alpine AS builder

WORKDIR /app

COPY . .

RUN go install . 

FROM alpine:latest

ARG VERSION=dev
ARG VCS_REF=dev
ARG BUILD_DATE=unknown
ARG LABEL_MAINTAINER="Justin Azoff <justin.azoff@gmail.com>"
ARG LABEL_IMAGE_SOURCE="JustinAzoff/ssh-auth-logger"
ARG LABEL_IMAGE_URL="justinazoff/ssh-auth-logger"

LABEL maintainer="$LABEL_MAINTAINER" \
      org.opencontainers.image.title="ssh-auth-logger" \
      org.opencontainers.image.description="A low/zero interaction ssh authentication logging honeypot" \
      org.opencontainers.image.source="https://github.com/$LABEL_IMAGE_SOURCE" \
      org.opencontainers.image.url="https://hub.docker.com/r/$LABEL_IMAGE_URL" \
      org.opencontainers.image.documentation="https://github.com/$LABEL_IMAGE_SOURCE#" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.version=$VERSION

ENV VERSION=$VERSION
ENV USER=nobody
ENV SSHD_BIND=:2222
ENV TELNET_BIND=:2323

COPY --from=builder /go/bin/ssh-auth-logger /go/bin/ssh-auth-logger

RUN touch /var/log/ssh-auth-logger.log && \
    chown $USER /var/log/ssh-auth-logger.log && \
    chmod 644 /var/log/ssh-auth-logger.log

USER $USER

EXPOSE 2222 2323

CMD test -f /var/log/ssh-auth-logger.log || { echo 'Creating log file...' && touch /var/log/ssh-auth-logger.log ; }; /go/bin/ssh-auth-logger 2>&1 | tee -a /var/log/ssh-auth-logger.log