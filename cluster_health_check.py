__author__ = 'shu2003'

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

        TENANT_NAME_HDR = 'X-Avi-Tenant'
        DEF_TIMEOUT     = 30
        DEF_HEADERS     = {'Content-type': 'application/json', TENANT_NAME_HDR: 'admin', }

        session = None
        results_dic = {}
        print "+Creating a session to AVI Controller %s" %avi_vip

        try:
                requests.packages.urllib3.disable_warnings()
                auth    = [avi_user, avi_passwd]
                session = requests.session()
                session.auth = requests.auth.HTTPBasicAuth(*auth)
                session.headers.update(DEF_HEADERS)
                avic = session
                return avic

        except Exception as api_excep:
            print "!!!!Exception Occurred while trying to create a session to AVI controlelr!!!"
            print api_excep



def _check_cluster_health(avic, avi_vip):
        health_ok = 1
        results_dic = {}

        try:
                avi_uri = 'https://%s' % (avi_vip) + '/api/cluster/runtime'


                resp = avic.get(avi_uri, verify=False)
                resp_text = json.loads(resp.text)['cluster_state']
                resp2_text = json.loads(resp.text)['node_states']

                print "+++++++++Checking AVI cluster Status++++++++++"
                print "+Retrieving cluster health via API call %s" %avi_uri
                print "Current Cluster Status  : %s" %resp_text['state']
                print "Cluster is up since     : %s" %resp_text['up_since']

                print "+++++++++Checking cluster Member Status++++++++++"
                for i in range(0,3):
                   print resp2_text[i]['name'] + " :   " + resp2_text[i]['role'] + "  "  + resp2_text[i]['state'] + "  Up Since  " "    " + resp2_text[i]['up_since']


                avic.close()

                print "\n"

                if resp_text['state'] == "CLUSTER_UP_HA_ACTIVE":
                    health_ok = 0
                    print "+++++++++Cluster is healthy ++++++++++"
                else:
                    print "+++++++++Cluster is Unhealthy and the state is %s ++++++++++"%resp_text['state']




        except Exception as api_excep:
            print "!!!!Exception Occurred while getting cluster status!!!"
            print api_excep

        return health_ok

if __name__=='__main__':


    print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"
    print "+++++++++Checking AVI Controller cluster+++++++++++++++++++"
    print "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++"



    parser = argparse.ArgumentParser(description='Script to check AVI cluster health')
    parser.add_argument('-i','--ip', help='AVI controller VIP IP',required=True)
    parser.add_argument('-u','--user',help='Controller admin user', required=True)
    parser.add_argument('-p','--passwd',help='Controller admin password', required=True)
    args = parser.parse_args()

    login_session = _create_session(args.ip, args.user, args.passwd)
    _check_cluster_health(login_session, args.ip)
    login_session.close()
