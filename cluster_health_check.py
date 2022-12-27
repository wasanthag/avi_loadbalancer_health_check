#!/usr/bin/env python
# Filename: cluster_health_check.py
# usage python cluster_health_check.py -i <controller vip ip> -u <admin user> -p <password>
# returns 0 if cluster is healthy or 1 if not

__author__ = 'shu2003'

import requests
import json
import sys
import argparse



def _create_session(avi_vip, avi_user, avi_passwd):


        print(f"+Creating a session to AVI Controller {avi_vip}\n")
        avi_uri = f"https://{avi_vip}/login"
        try:
                requests.packages.urllib3.disable_warnings()
                login = requests.post(avi_uri, verify=False,
                                      data={'username': avi_user, 'password': avi_passwd})
                return login

        except Exception as api_excep:
            print("!!!!Exception Occurred while trying to create a session to AVI controlelr!!!")
            print(api_excep)


def _check_cluster_health(avic, avi_vip):
        health_ok = 1
        results_dic = {}

        try:
                avi_uri = f"https://{avi_vip}/api/cluster/runtime"

                resp = requests.get(avi_uri, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                # resp = avic.get(avi_uri, verify=False)
                resp_text = json.loads(resp.text)['cluster_state']
                resp2_text = json.loads(resp.text)['node_states']

                print("+++++++++Checking AVI cluster Status++++++++++")
                print(f"+Retrieving cluster health via API call {avi_uri}")
                print(f"Current Cluster Status  : {resp_text['state']}")
                print(f"Cluster is up since     : {resp_text['up_since']}")

                print("+++++++++Checking cluster Member Status++++++++++")
                for node in resp2_text:
                   print(f"{node['name']} :   {node['role']}  {node['state']}  Up Since    {node['up_since']}")


                avic.close()

                print()

                if resp_text['state'] == "CLUSTER_UP_HA_ACTIVE":
                    health_ok = 0
                    print("+++++++++Cluster is healthy ++++++++++")
                else:
                    print(f"+++++++++Cluster is Unhealthy and the state is {resp_text['state']} ++++++++++")




        except Exception as api_excep:
            print("!!!!Exception Occurred while getting cluster status!!!")
            print(api_excep)

        return health_ok

if __name__=='__main__':


    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
    print("+++++++++Checking AVI Controller cluster+++++++++++++++++++")
    print("+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")



    parser = argparse.ArgumentParser(description='Script to check AVI cluster health')
    parser.add_argument('-i','--ip', help='AVI controller VIP IP',required=True)
    parser.add_argument('-u','--user',help='Controller admin user', required=True)
    parser.add_argument('-p','--passwd',help='Controller admin password', required=True)
    args = parser.parse_args()

    login_session = _create_session(args.ip, args.user, args.passwd)
    _check_cluster_health(login_session, args.ip)
    login_session.close()
