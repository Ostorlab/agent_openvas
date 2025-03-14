FROM immauss/openvas:22.4.40

ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8

COPY scripts/* /scripts/

RUN apt-get update && apt-get install -y virtualenv
COPY requirement.txt /requirement.txt
RUN python3.11 -m virtualenv -p python3.11 /venv
RUN /venv/bin/python3.11 -m pip install --upgrade pip
RUN /venv/bin/python3.11 -m pip install -r /requirement.txt
RUN mkdir -p /app/agent
ENV PYTHONPATH=/app
COPY agent /app/agent
COPY ostorlab.yaml /app/agent/ostorlab.yaml
WORKDIR /app
ENTRYPOINT ["/usr/bin/env"]
CMD ["/venv/bin/python3.11", "/app/agent/openvas_agent.py"]
