FROM immauss/openvas:21.04.09

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

COPY scripts/* /scripts/

RUN apt-get update &&  python3 -m pip install --upgrade pip
COPY requirement.txt /requirement.txt
RUN python3 -m pip install -r /requirement.txt
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
ENTRYPOINT ["/usr/bin/env"]
CMD ["python3", "/app/agent/openvas_agent.py"]
