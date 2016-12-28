# ssh_auth_logger
#
# VERSION               0.1

FROM alpine
MAINTAINER Justin Azoff <justin.azoff@gmail.com>

ADD ssh-auth-logger_linux_amd64 /ssh-auth-logger

EXPOSE 22
ENTRYPOINT ["/ssh-auth-logger"]
