# Container image that runs your code
FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive
ARG USERNAME=prowler
ARG USERID=34000

# Update stuff and install needed packages
RUN apt-get update \
  && apt-get upgrade -y \
  && apt-get install python3-pip -y \
  && apt-get install bash curl jq file -y \
  && apt-get install git -y \
  && mkdir -p /prowler \
  && git clone https://github.com/toniblyx/prowler /prowler \
  && pip3 install --upgrade setuptools \
  && pip3 install --upgrade virtualenv \
  && pip3 install --upgrade PyYAML \
  && pip3 install --upgrade yorm \
  && pip3 install --upgrade jinja2 \
  && pip3 install --upgrade boto3 \
  && pip3 install --upgrade pyyaml \
  && pip3 install --upgrade awscli \
  && pip3 install --upgrade boto3 \
  && pip3 install --upgrade ansi2html \
  && pip3 install --upgrade detect-secrets \
  && pip3 install cfn_flip \
  && pip3 freeze

RUN addgroup --gid ${USERID} ${USERNAME} \
  && useradd --shell /bin/bash -g ${USERNAME} ${USERNAME} \
  && chown -R prowler /prowler/

# Copies your code file from your action repository to the filesystem path `/` of the container
COPY launch.sh /entrypoint.sh

# Switch to prowler user
USER ${USERNAME}

# Code file to execute when the docker container starts up (`entrypoint.sh`)
ENTRYPOINT ["/entrypoint.sh"]
CMD []
