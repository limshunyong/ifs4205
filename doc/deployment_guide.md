# IFS4205 Capstone Project Deployment Guide
Last updated: 1/9/2018

- Set Up Docker Swarm
- Depoly Containers

> This document is written for deployment on production servers (i.e. the given Sunfire VMs).
For local development, simply use `docker-compose`. For more information, read the tutorial [here](https://docs.docker.com/compose/gettingstarted/).

### Set Up Docker Swarm
#### Prerequisites
- You should have sudo/root access on the remote machines
- Have Docker CE installed on all nodes. (https://docs.docker.com/install/linux/docker-ce/centos/#install-using-the-repository)

#### Configure Firewalls
The hosts in the docker swarm use the following ports to communicate:

- TCP port 2377 for cluster management communications
- TCP and UDP port 7946 for communication among nodes
- UDP port 4789 for overlay network traffic

Execute the following commands on all hosts to add rules to the firewall. Here we use CentOS as an example:
```
sudo firwall-cmd --zone=public --add-port=2377/tcp --permanent 
sudo firwall-cmd --zone=public --add-port=7946/tcp --permanent 
sudo firwall-cmd --zone=public --add-port=7946/udp --permanent 
sudo firwall-cmd --zone=public --add-port=4789/udp --permanent 
sudo firewall-cmd --reload
```

#### Configure Swarm Mananer and Add Worker Nodes
Firstly, choose a node to be the manager node and run the command beblow. Notice that `--advertise-addr` only accepts an IP address.


```
> docker swarm init --advertise-addr 172.25.76.1

Swarm initialized: current node (xxxxxxxxxxxxxxxxxxxx) is now a manager.

To add a worker to this swarm, run the following command:

    docker swarm join --token xxxxxxxxxxxxxxuxxxxxxxxxxxxxxxx 172.25.76.1:2377

To add a manager to this swarm, run 'docker swarm join-token manager' and follow the instructions.
```
Execute the given command on the worker nodes individually. If joined successfully, you shall see a message saying `This node joined a swarm as a worker`.

#### Monitor A Swarm
For simple visualisation of the swarm state such as which container is running on which node, we can use `docker-swarm-visualizer`. It is a docker image ready to be used out-of-box. To start the web interface, run the following command on the manager node:

> TODO: Add swarm visualiser to docker compose

```
docker service create \
  --name=viz \
  --publish=8080:8080/tcp \
  --constraint=node.role==manager \
  --mount=type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock \
  dockersamples/visualizer
```
You should now be able to visit the web dashboard on `[any of the nodes' IP address]:8080`.
