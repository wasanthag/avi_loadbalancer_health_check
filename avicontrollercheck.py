#!/usr/bin/env python
# Filename: avicontrollercheck.py
__author__ = 'shu2003'

import requests
import json
import argparse




def _create_session(avi_vip, avi_user, avi_passwd):


        print "+Creating a session to AVI Controller %s" %avi_vip
        print "\n"
        avi_uri = 'https://%s' % (avi_vip) + '/login'
        try:
                requests.packages.urllib3.disable_warnings()
                login = requests.post(avi_uri, verify=False,
                                      data={'username': avi_user, 'password': avi_passwd})
                return login

        except Exception as api_excep:
            print "!!!!Exception Occurred while trying to create a session to AVI controlelr!!!"
            print api_excep

def _check_configs(avic, avi_vip):

        results_dic = {}
        results2_dic = {}

        try:
                avi_uri0 = 'https://%s' % (avi_vip) + '/api/cluster/version'
                avi_uri = 'https://%s' % (avi_vip) + '/api/serviceenginegroup'
                avi_uri2 = 'https://%s' % (avi_vip) + '/api/systemconfiguration'
                avi_uri3 = 'https://%s' % (avi_vip) + '/api/cloud'


                print "+++++++++Checking AVI cluster config parameters++++++++"

                print "+Retrieving configs via API call %s" %avi_uri0
                resp0 = requests.get(avi_uri0, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                resp0_text = json.loads(resp0.text)
                print "Cluster Software Version is       : %s" %resp0_text['Version']
                print "Cluster Software build is         : %s" %resp0_text['build']

                resp = requests.get(avi_uri, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                resp_text = json.loads(resp.text)['results']
                results_dic = resp_text
                print "+Retrieving configs via API call %s" %avi_uri
                print "Cluster Auto Rebalance is set to  : %s" %results_dic[0]['auto_rebalance']
                print "Cluster HA Mode is set to         : %s" %results_dic[0]['ha_mode']
                print "MAX SE count is set to            : %s" %results_dic[0]['max_se']
                print "MAX Virtual services per SE       : %s" %results_dic[0]['max_vs_per_se']
                print "SE Redundancy is set to           : %s" %results_dic[0]['vs_host_redundancy']
                print "Memory per SE is set to           : %s" %results_dic[0]['memory_per_se']


                print "+Retrieving configs via API call %s" %avi_uri2
                resp2 = requests.get(avi_uri2, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                resp2_text = json.loads(resp2.text)['global_tenant_config']
                print "SE in Provider Context is set to   : %s" %resp2_text['se_in_provider_context']
                print "Tenant VRF configuration is set to : %s" %resp2_text['tenant_vrf']

                print "+Retrieving configs via API call %s" %avi_uri3
                resp3 = requests.get(avi_uri3, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                resp3_text = json.loads(resp3.text)['results']
                results_dic3 = resp3_text
                results_dic4 = results_dic3[0]['openstack_configuration']
                print "Import Keystone tenants set to   : %s" %results_dic4['import_keystone_tenants']

                avic.close()


        except Exception as api_excep:
            print "!!!!Exception Occurred while getting configs from AVI API!!!"
            print api_excep

def _check_cluster_health(avic, avi_vip):
        results_dic = {}

        try:
                avi_uri = 'https://%s' % (avi_vip) + '/api/cluster/runtime'


                resp = requests.get(avi_uri, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                resp_text = json.loads(resp.text)['cluster_state']
                resp2_text = json.loads(resp.text)['node_states']

                print "+++++++++Checking AVI cluster Status++++++++++"
                print "+Retrieving cluster health via API call %s" %avi_uri
                print "Current Cluster Status  : %s" %resp_text['state']
                print "Cluster is up since     : %s" %resp_text['up_since']

                print "+++++++++Checking cluster Member Status++++++++++"
                for i in range(0,3):
                   print resp2_text[i]['name'] + " :   " + resp2_text[i]['role'] + "  "  + resp2_text[i]['state'] + "  Up Since  " "    " + resp2_text[i]['up_since']


                print "\n"

                avic.close()


        except Exception as api_excep:
            print "!!!!Exception Occurred while getting configs from serviceenginegroup!!!"
            print api_excep

def _check_tenant_configs(avic, avi_vip):

        results_dic = {}
        results_list = {}
        se_list = []

        try:
                avi_uri0 = 'https://%s' % (avi_vip) + '/api/tenant'

                print
                print "+++++++++Checking AVI Tenant configs++++++++"
                print

                print "+Retrieving configs via API call %s" %avi_uri0

                resp = requests.get(avi_uri0, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                resp_text = json.loads(resp.text)['results']
                results_list = resp_text
                for i in results_list:
                    if 'config_settings' in i:
                        print "+++++++Configs for tenant %s with UUID: %s +++++++" %(i['name'],i['uuid'])
                        virt_svc_url = 'https://%s' % (avi_vip) + '/api/tenant/' + i['uuid'] + '/virtualservice'
                        resp2 = requests.get(virt_svc_url, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                        resp2_text = json.loads(resp2.text)['results']

                        for j in resp2_text:
                            print "+++++++++Virtual services configs++++++++"
                            print "UUID                  : %s" % j['uuid']
                            print "Name                  : %s" % j['name']
                            print "enabled               : %s" % j['enabled']
                            print "port_uuid             : %s" % j['port_uuid']
                            print "weight                : %s" % j['weight']
                            print "subnet_uuid           : %s" % j['subnet_uuid']
                            #print "delay_fairness               : %s" % j['delay_fairness']
                            #print "avi_allocated_vip            : %s" % j['avi_allocated_vip']
                            #print "avi_allocated_fip            : %s" % j['avi_allocated_fip']
                            #print "max_cps_per_client           : %s" % j['max_cps_per_client']
                            #print "redis_db                     : %s" % j['redis_db']
                            #print "type                         : %s" % j['type']
                            #print "requested_resource           : %s" % j['requested_resource']
                            if 'description' in j:
                                print "description           : %s" % j['description']
                            print "subnet                 : %s" % j['subnet']
                            #print "redis_port                   : %s" % j['redis_port']
                            #print "auto_allocate_floating_ip    : %s" % j['auto_allocate_floating_ip']
                            print "address                : %s" % j['address']
                            print "services               : %s" % j['services']
                            #print "ip_address                   : %s" % j['ip_address']
                            #print "limit_doser                  : %s" % j['limit_doser']
                            #print "enable_autogw                : %s" % j['enable_autogw']
                            #print "auto_allocate_ip             : %s" % j['auto_allocate_ip']
                            #print "analytics_policy             : %s" % j['analytics_policy']
                            #print "redis_ip                     : %s" % j['redis_ip']

                            # print "se_list  : %s" % j['se_list']
                            if 'se_list' in j:
                                se_list = j['se_list']
                                for x in se_list:
                                    print "+++++++++SE Configs+++++++++"
                                    se_url = x['se_ref']
                                    se_resp = requests.get(se_url, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                                    se_resp_text = json.loads(se_resp.text)
                                    # print "Additional SE  configs    :"
                                    print "name                 : %s" % se_resp_text['name']
                                    print "mgmt_vnic            : %s" % se_resp_text['mgmt_vnic']['vnic_networks']
                                    # print "flavor                    : %s" % se_resp_text['flavor']
                                    # print "resources                 : %s" % se_resp_text['resources']
                                    # print "hb_status                 : %s" % se_resp_text['hb_status']
                                    print "state_name           : %s" % se_resp_text['state_name']
                                    print "oper_status          : %s" % se_resp_text['oper_status']['state']
                                    print "oper_status_reason   : %s" % se_resp_text['oper_status']['reason']
                                    # print "vinfra_discovered         : %s" % se_resp_text['vinfra_discovered']
                                    print "power_state          : %s" % se_resp_text['power_state']
                                    print "creation_in_progress : %s" % se_resp_text['creation_in_progress']

                                    #print "vnic  configs            :"
                                    #print " vnic1                   : %s" % x['vnic'][0]
                                    #print " vnic2                   : %s" % x['vnic'][1]
                                    #print " vnic3                   : %s" % x['vnic'][2]
                                    print "vip_intf_mac         : %s" %x['vip_intf_mac']
                                    #print "delete_in_progress       : %s" %x['delete_in_progress']
                                    print "is_primary           : %s" %x['is_primary']
                                    #print "sec_idx                  : %s" %x['sec_idx']
                                    print "is_standby           : %s" %x['is_standby']
                                    #print "vip_subnet_mask          : %s" %x['vip_subnet_mask']
                                    #print "se_ref                   : %s" %x['se_ref']
                                    #print "memory                   : %s" %x['memory']
                                    #print "pending_download         : %s" %x['pending_download']
                                    #print "is_connected             : %s" %x['is_connected']
                                del se_list



                            print "\n"


                        pool_url = 'https://%s' % (avi_vip) + '/api/tenant/' + i['uuid'] + '/pool'
                        pool_resp = requests.get(pool_url, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                        pool_resp_text = json.loads(pool_resp.text)['results']
                        print "+++++++++Pool configs++++++++"
                        for y in pool_resp_text:
                            print "name                   : %s" % y['name']
                            if 'description' in y:
                                print "description                  : %s" % y['description']
                            print "UUID                   : %s" % y['uuid']
                            print "enabled                : %s" % y['enabled']
                            print "lb_algorithm           : %s" % y['lb_algorithm']
                            print "server_count           : %s" % y['server_count']
                            if 'servers' in y:
                                #print "servers                      : %s" % y['servers']
                                for a in range(0,y['server_count']):
                                    print "server %i configs" %(a + 1)
                                    print "name:        : %s" %y['servers'][a]['hostname']
                                    print "ext_uuid:    : %s" % y['servers'][a]['external_uuid']
                                    print "ip:          : %s" % y['servers'][a]['ip']
                                    print "enabled:     : %s" % y['servers'][a]['enabled']
                                    print "port:        : %s" % y['servers'][a]['port']
                                    a = a +1

                            if 'health_monitor_refs' in y:
                                #print "health_monitor_refs          : %s" % y['health_monitor_refs']
                                hm_list = y['health_monitor_refs']

                                hm_split = hm_list[0].split('/api')

                                hm_url = 'https://%s' % (avi_vip) + '/api/tenant/' + i['uuid'] + hm_split[1]
                                hm_resp = requests.get(hm_url, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                                hm_resp_text = json.loads(hm_resp.text)

                                print "\n"
                                print "+++++++++Health Monitor configs++++++++"
                                print "name                         : %s" % hm_resp_text['name']
                                print "UUID                         : %s" % hm_resp_text['uuid']
                                print "Type                         : %s" % hm_resp_text['type']


                        print "\n"



                #for pool
                #virt_svc_url = 'https://%s' % (avi_vip) + '/api/tenant/' + i['uuid'] + '/pool'

                avic.close()


        except Exception as api_excep:
            print "!!!!Exception Occurred while getting configs from AVI API!!!"
            print api_excep


if __name__=='__main__':



    parser = argparse.ArgumentParser(
        description='AVI Cluster check Tool')
    parser.add_argument('-i', '--ip', required=True, help="AVI Controller VIP IP")
    parser.add_argument('-u', '--user', required=True, help="AVI Controller VIP User")
    parser.add_argument('-p', '--passwd', required=True, help="AVI Controller VIP Password")
    parser.add_argument('-o', '--option', choices=('health', 'cluster_configs', 'tenant_configs'), required=True, help="Various configs checks")

    args = parser.parse_args()

    avi_controller_vip = args.ip
    avi_controller_passwd = args.passwd
    avi_user = args.user


    if args.option == 'health':
        print "++++++ Checking AVI cluster Health +++++++\n"
        login_session = _create_session(avi_controller_vip, avi_user, avi_controller_passwd)
        _check_cluster_health(login_session, avi_controller_vip)
        login_session.close()

    elif args.option == 'cluster_configs':
        print "++++++ Checking AVI cluster config parameters ++++++\n"
        login_session = _create_session(avi_controller_vip, avi_user, avi_controller_passwd)
        _check_configs(login_session, avi_controller_vip)
        login_session.close()

    elif args.option == 'tenant_configs':
        print "++++++ Checking AVI cluster config parameters ++++++\n"
        login_session = _create_session(avi_controller_vip, avi_user, avi_controller_passwd)
        _check_tenant_configs(login_session, avi_controller_vip)
        login_session.close()

