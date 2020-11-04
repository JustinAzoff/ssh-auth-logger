# ssh_auth_logger
FROM justinazoff/ssh-auth-logger
MAINTAINER Team Stingar <team-stingar@duke.edu>

ENV SSHAUTHLOGGER_JSON "/etc/ssh-auth-logger/ssh-auth-logger.json"
ENV SSHAUTHLOGGER_CONFIG "/opt/ssh-auth-logger.cfg"
ENV SHD_BIND ":22222"

WORKDIR /opt
COPY requirements.txt .
RUN apk --no-cache add python3 bash git jq
RUN python3 -m pip install git+https://github.com/CommunityHoneyNetwork/hpfeeds3.git
RUN python3 -m pip install -r /opt/requirements.txt
COPY entrypoint.sh /opt/entrypoint.sh
COPY hpfeeds_output.py /opt/hpfeeds_output.py
COPY conf /opt/conf
EXPOSE 22222
ENTRYPOINT ["/opt/entrypoint.sh"]
