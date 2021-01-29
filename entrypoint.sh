#!/bin/bash

trap "exit 130" SIGINT
trap "exit 137" SIGKILL
trap "exit 143" SIGTERM

set -o errexit
set -o nounset
set -o pipefail

main () {
  echo "Starting ssh-auth-logger"
  DEBUG=${DEBUG:-false}
  if [[ ${DEBUG} == "true" ]]
  then
    set -o xtrace
    SSHAUTHLOGGER_DEBUG="-d"
  else
    SSHAUTHLOGGER_DEBUG=""
  fi

  # Register this host with CHN if needed
  chn-register.py \
      -p ssh-auth-logger \
      -d "${DEPLOY_KEY}" \
      -u "${CHN_SERVER}" -k \
      -o "${SSHAUTHLOGGER_JSON}" \
      -i "${REPORTED_IP}"
      local uid="$(cat ${SSHAUTHLOGGER_JSON} | jq -r .identifier)"
      local secret="$(cat ${SSHAUTHLOGGER_JSON} | jq -r .secret)"

      # Keep old var names, but create also create some new ones that
      # containedenv can understand

      export SSHAUTHLOGGER_hpfeeds__enabled="True"
      export SSHAUTHLOGGER_hpfeeds__server="${FEEDS_SERVER}"
      export SSHAUTHLOGGER_hpfeeds__port="${FEEDS_SERVER_PORT:-10000}"
      export SSHAUTHLOGGER_hpfeeds__ident="${uid}"
      export SSHAUTHLOGGER_hpfeeds__secret="${secret}"
      export SSHAUTHLOGGER_hpfeeds__tags="${TAGS}"
      export SSHAUTHLOGGER_hpfeeds__reported_ip="${REPORTED_IP}"

      # Write out custom conpot config
      containedenv-config-writer.py \
        -p SSHAUTHLOGGER_ \
        -f ini \
        -r /opt/conf/ssh-auth-logger.cfg.template \
        -o /opt/ssh-auth-logger.cfg

  exec /ssh-auth-logger 2>&1 | /opt/hpfeeds_output.py ${SSHAUTHLOGGER_DEBUG}
}

main "$@"

