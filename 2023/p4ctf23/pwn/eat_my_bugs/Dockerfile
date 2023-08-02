FROM patryk4815/nsjail:23.04

RUN /usr/bin/apt-get update \
    && /usr/bin/apt-get upgrade --assume-yes \
    && /usr/bin/apt-get install --assume-yes cgroup-tools hashcash locales

WORKDIR /home/eat_bugs
COPY eat_bugs entrypoint.sh ./
COPY flag.txt ./

EXPOSE 4000/tcp
CMD /home/eat_bugs/entrypoint.sh
