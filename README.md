# avi_cluster_checks
scripts to monitor AVI networks cloud controller cluster and config parameters

There are 2 scripts in this repo.

1) avicontrollercheck.py takes ip address/user name/password of the AVI controller cluster and outputs 
- Cluster health
- cluster config parameters
- tenant configs including virtual services, pools, Service engine configs etc..

```
$ python avicontrollercheck.py -h
usage: avicontrollercheck.py [-h] -i IP -u USER -p PASSWD -o
                             {health,cluster_configs,tenant_configs}

AVI Cluster check Tool

optional arguments:
  -h, --help            show this help message and exit
  -i IP, --ip IP        AVI Controller VIP IP
  -u USER, --user USER  AVI Controller VIP User
  -p PASSWD, --passwd PASSWD
                        AVI Controller VIP Password
  -o {health,cluster_configs,tenant_configs}, --option {health,cluster_configs,tenant_configs}
                        Various configs checks
```

2) cluster_health_check.py
This is similar to the cluster health check functionality provided by the 1) but in summary format. It can be used as a Nagios plugin.

