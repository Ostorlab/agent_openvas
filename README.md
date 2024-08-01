
<h1 align="center">Agent OpenVas</h1>

<p align="center">
<img src="https://img.shields.io/badge/License-Apache_2.0-brightgreen.svg">
<img src="https://img.shields.io/github/languages/top/ostorlab/agent_openvas">
<img src="https://img.shields.io/github/stars/ostorlab/agent_openvas">
<img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg">
</p>

_OpenVAS is a network security and vulnerability scanner._

---

<p align="center">
<img src="https://github.com/Ostorlab/agent_openvas/blob/main/images/logo.png" alt="agent-openvas" />
</p>

This repository is an implementation of the OpenVas agent.

## Getting Started
To perform your first scan, simply run the following command.
```shell
oxo scan run --install --agent agent/ostorlab/openvas ip 8.8.8.8
```

This command will download and install `agent/ostorlab/openvas` and target the ip `8.8.8.8`.
For more information, please refer to the [OXO Documentation](https://oxo.ostorlab.co/docs)


## Usage

Agent OpenVas can be installed directly from the oxo agent store or built from this repository.

 ### Install directly from oxo agent store

 ```shell
 oxo agent install agent/ostorlab/openvas
 ```

You can then run the agent with the following command:
```shell
oxo scan run --agent agent/ostorlab/openvas ip 8.8.8.8
```


### Build directly from the repository

 1. To build the openvas agent you need to have [oxo](https://pypi.org/project/ostorlab/) installed in your machine.  if you have already installed oxo, you can skip this step.

```shell
pip3 install ostorlab
```

 2. Clone this repository.

```shell
git clone https://github.com/Ostorlab/agent_openvas.git && cd agent_openvas
```

 3. Build the agent image using oxo cli.

 ```shell
 oxo agent build --file=ostorlab.yaml
 ```
 You can pass the optional flag `--organization` to specify your organisation. The organization is empty by default.

 4. Run the agent using one of the following commands:
	 * If you did not specify an organization when building the image:
      ```shell
      oxo scan run --agent agent//openvas ip 8.8.8.8
      ```
	 * If you specified an organization when building the image:
      ```shell
      oxo scan run --agent agent/[ORGANIZATION]/openvas ip 8.8.8.8
      ```


## License
[Apache](./LICENSE)

