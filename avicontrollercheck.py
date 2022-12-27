#!/usr/bin/env python
# Filename: avicontrollercheck.py
__author__ = 'shu2003'

from opcode import hasconst
from re import I
import requests
import json
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

def _check_configs(avic, avi_vip):

        results_dic = {}
        results2_dic = {}

        try:
                avi_uri0 = f"https://{avi_vip}/api/cluster/version"
                avi_uri = f"https://{avi_vip}/api/serviceenginegroup"
                avi_uri2 = f"https://{avi_vip}/api/systemconfiguration"
                avi_uri3 = f"https://{avi_vip}/api/cloud"


                print("+++++++++Checking AVI cluster config parameters++++++++")

                print(f"+Retrieving configs via API call {avi_uri0}")
                resp0 = requests.get(avi_uri0, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                resp0_text = json.loads(resp0.text)
                print(f"Cluster Software Version is       : {resp0_text['Version']}")
                print(f"Cluster Software build is         : {resp0_text['build']}")

                resp = requests.get(avi_uri, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                resp_text = json.loads(resp.text)['results']
                results_dic = resp_text
                print(f"+Retrieving configs via API call {avi_uri}")
                print(f"Cluster Auto Rebalance is set to  : {results_dic[0]['auto_rebalance']}")
                print(f"Cluster HA Mode is set to         : {results_dic[0]['ha_mode']}")
                print(f"MAX SE count is set to            : {results_dic[0]['max_se']}")
                print(f"MAX Virtual services per SE       : {results_dic[0]['max_vs_per_se']}")
                print(f"SE Redundancy is set to           : {results_dic[0]['vs_host_redundancy']}")
                print(f"Memory per SE is set to           : {results_dic[0]['memory_per_se']}")


                print(f"+Retrieving configs via API call {avi_uri2}")
                resp2 = requests.get(avi_uri2, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                resp2_text = json.loads(resp2.text)['global_tenant_config']
                print(f"SE in Provider Context is set to   : {resp2_text['se_in_provider_context']}")
                print(f"Tenant VRF configuration is set to : {resp2_text['tenant_vrf']}")

                print(f"+Retrieving configs via API call {avi_uri3}")
                resp3 = requests.get(avi_uri3, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                resp3_text = json.loads(resp3.text)['results']
                results_dic3 = resp3_text
                for cloud in resp3_text:
                    print(f"+++++++++V-Type {cloud['vtype']}+++++++++++++++++")
                    print(f"+Name                          : {cloud['name']}")
                    print(f"+DHCP enabled                  : {cloud['dhcp_enabled']}")
                    print(f"+MTU                           : {cloud['mtu']}")
                    print(f"+Prefer static_routes          : {cloud['prefer_static_routes']}")
                    print(f"+Enable vip static_routes      : {cloud['enable_vip_static_routes']}")
                    if hasattr(cloud,'obj_name_prefix' ):
                        print(f"+Object name prefix            : {cloud['obj_name_prefix']}")
                    print(f"+License type                  : {cloud['license_type']}")
                    print(f"+License tier                  : {cloud['license_tier']}")
                    print(f"+State based dns registration  : {cloud['state_based_dns_registration']}")
                    print(f"+ip6 autocfg enabled           : {cloud['ip6_autocfg_enabled']}")
                    print(f"+Autoscale polling interval    : {cloud['autoscale_polling_interval']}")
                    if hasattr(cloud,'openstack_configuration' ):
                        print("Import Keystone tenants set to   : {cloud['openstack_configuration']['import_keystone_tenants']}")
                avic.close()


        except Exception as api_excep:
            print("!!!!Exception Occurred while getting configs from AVI API!!!")
            print(api_excep)

def _check_cluster_health(avic, avi_vip):
        results_dic = {}

        try:
                avi_uri = f"https://{avi_vip}/api/cluster/runtime"

                resp = requests.get(avi_uri, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                resp_text = json.loads(resp.text)['cluster_state']
                resp2_text = json.loads(resp.text)['node_states']
                print("+++++++++Checking AVI cluster Status++++++++++")
                print(f"+Retrieving cluster health via API call {avi_uri}")
                print(f"Current Cluster Status  : {resp_text['state']}")
                print(f"Cluster is up since     : {resp_text['up_since']}")

                print("+++++++++Checking cluster Member Status++++++++++")
                
                for node in resp2_text:
                   print(f"{node['name']} :   {node['role']}  {node['state']}  Up Since      {node['up_since']}")


                print()

                avic.close()


        except Exception as api_excep:
            print("!!!!Exception Occurred while getting configs from serviceenginegroup!!!")
            print(api_excep)

def _check_tenant_configs(avic, avi_vip):

        results_dic = {}
        results_list = {}
        se_list = []

        try:
                avi_uri0 = f"https://{avi_vip}/api/tenant"

                print
                print("+++++++++Checking AVI Tenant configs++++++++")
                print

                print(f"+Retrieving configs via API call {avi_uri0}")

                resp = requests.get(avi_uri0, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                resp_text = json.loads(resp.text)['results']
                results_list = resp_text
                for i in results_list:
                    if 'config_settings' in i:
                        print(f"+++++++Configs for tenant {i['name']} with UUID: {i['uuid']} +++++++")
                        virt_svc_url = f"https://{avi_vip}/api/tenant/{i['uuid']}/virtualservice"
                        resp2 = requests.get(virt_svc_url, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                        resp2_text = json.loads(resp2.text)['results']

                        for j in resp2_text:
                            print("+++++++++Virtual services configs++++++++")
                            print(f"UUID                  : {j['uuid']}")
                            print(f"Name                  : {j['name']}")
                            print(f"enabled               : {j['enabled']}")
                            print(f"port_uuid             : {j['port_uuid']}")
                            print(f"weight                : {j['weight']}")
                            print(f"subnet_uuid           : {j['subnet_uuid']}")
                            #print(f"delay_fairness               : {j['delay_fairness']}")
                            #print(f"avi_allocated_vip            : {j['avi_allocated_vip']}")
                            #print(f"avi_allocated_fip            : {j['avi_allocated_fip']}")
                            #print(f"max_cps_per_client           : {j['max_cps_per_client']}")
                            #print(f"redis_db                     : {j['redis_db']}")
                            #print(f"type                         : {j['type']}")
                            #print(f"requested_resource           : {j['requested_resource']}")
                            if 'description' in j:
                                print(f"description           : {j['description']}")
                            print(f"subnet                 : {j['subnet']}")
                            #print(f"redis_port                   : {j['redis_port']}")
                            #print(f"auto_allocate_floating_ip    : {j['auto_allocate_floating_ip']}")
                            print(f"address                : {j['address']}")
                            print(f"services               : {j['services']}")
                            #print(f"ip_address                   : {j['ip_address']}")
                            #print(f"limit_doser                  : {j['limit_doser']}")
                            #print(f"enable_autogw                : {j['enable_autogw']}")
                            #print(f"auto_allocate_ip             : {j['auto_allocate_ip']}")
                            #print(f"analytics_policy             : {j['analytics_policy']}")
                            #print(f"redis_ip                     : {j['redis_ip']}")

                            #print(f"se_list  : {j['se_list']}")
                            if 'se_list' in j:
                                se_list = j['se_list']
                                for x in se_list:
                                    print("+++++++++SE Configs+++++++++")
                                    se_url = x['se_ref']
                                    se_resp = requests.get(se_url, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                                    se_resp_text = json.loads(se_resp.text)
                                    #print "Additional SE  configs    :"
                                    print(f"name                 : {se_resp_text['name']}")
                                    print(f"mgmt_vnic            : {se_resp_text['mgmt_vnic']['vnic_networks']}")
                                    #print(f"flavor                    : {se_resp_text['flavor']}")
                                    #print(f"resources                 : {se_resp_text['resources']}")
                                    #print(f"hb_status                 : {se_resp_text['hb_status']}")
                                    print(f"state_name           : {se_resp_text['state_name']}")
                                    print(f"oper_status          : {se_resp_text['oper_status']['state']}")
                                    print(f"oper_status_reason   : {se_resp_text['oper_status']['reason']}")
                                    #print(f"vinfra_discovered         : {se_resp_text['vinfra_discovered']}")
                                    print(f"power_state          : {se_resp_text['power_state']}")
                                    print(f"creation_in_progress : {se_resp_text['creation_in_progress']}")

                                    #print("vnic  configs            :")
                                    #print(f" vnic1                   : {x['vnic'][0]}")
                                    #print(f" vnic2                   : {x['vnic'][1]}")
                                    #print(f" vnic3                   : {x['vnic'][2]}")
                                    print(f"vip_intf_mac         : {['vip_intf_mac']}")
                                    #print(f"delete_in_progress       : {['delete_in_progress']}")
                                    print(f"is_primary           : {['is_primary']}")
                                    #print(f"sec_idx                  : {['sec_idx']}")
                                    print(f"is_standby           : {['is_standby']}")
                                    #print(f"vip_subnet_mask          : {['vip_subnet_mask']}")
                                    #print(f"se_ref                   : {['se_ref']}")
                                    #print(f"memory                   : {['memory']}")
                                    #print(f"pending_download         : {['pending_download']}")
                                    #print(f"is_connected             : {['is_connected']}")
                                del se_list


                            print()


                        pool_url = f"https://{avi_vip}/api/tenant/{i['uuid']}/pool"
                        pool_resp = requests.get(pool_url, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                        pool_resp_text = json.loads(pool_resp.text)['results']
                        print("+++++++++Pool configs++++++++")
                        for y in pool_resp_text:
                            print(f"name                   : {y['name']}")
                            if 'description' in y:
                                print(f"description                  : {y['description']}")
                            print(f"UUID                   : {y['uuid']}")
                            print(f"enabled                : {y['enabled']}")
                            print(f"lb_algorithm           : {y['lb_algorithm']}")
                            print(f"server_count           : {y['server_count']}")
                            if 'servers' in y:
                                #print(f "servers                      : {y['servers']}")
                                for a in range(0,y['server_count']):
                                    print(f"server {a + 1} configs")
                                    print(f"name:        : {y['servers'][a]['hostname']}")
                                    print(f"ext_uuid:    : {y['servers'][a]['external_uuid']}")
                                    print(f"ip:          : {y['servers'][a]['ip']}")
                                    print(f"enabled:     : {y['servers'][a]['enabled']}")
                                    print(f"port:        : {y['servers'][a]['port']}")
                                    a = a +1

                            if 'health_monitor_refs' in y:
                                #print(f"health_monitor_refs          : {y['health_monitor_refs']}")
                                hm_list = y['health_monitor_refs']

                                hm_split = hm_list[0].split('/api')

                                hm_url = f"https://{avi_vip}/api/tenant/{i['uuid']}{hm_split[1]}"
                                hm_resp = requests.get(hm_url, verify=False, cookies=dict(sessionid= avic.cookies['sessionid']))
                                hm_resp_text = json.loads(hm_resp.text)

                                print()
                                print("+++++++++Health Monitor configs++++++++")
                                print(f"name                         : {hm_resp_text['name']}")
                                print(f"UUID                         : {hm_resp_text['uuid']}")
                                print(f"Type                         : {hm_resp_text['type']}")

                        print()



                #for pool
                #virt_svc_url = f"https://{avi_vip}/api/tenant/{i['uuid']}/pool"

                avic.close()


        except Exception as api_excep:
            print("!!!!Exception Occurred while getting configs from AVI API!!!")
            print(api_excep)


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
        print("++++++ Checking AVI cluster Health +++++++\n")
        login_session = _create_session(avi_controller_vip, avi_user, avi_controller_passwd)
        _check_cluster_health(login_session, avi_controller_vip)
        login_session.close()

    elif args.option == 'cluster_configs':
        print("++++++ Checking AVI cluster config parameters ++++++\n")
        login_session = _create_session(avi_controller_vip, avi_user, avi_controller_passwd)
        _check_configs(login_session, avi_controller_vip)
        login_session.close()

    elif args.option == 'tenant_configs':
        print("++++++ Checking AVI cluster config parameters ++++++\n")
        login_session = _create_session(avi_controller_vip, avi_user, avi_controller_passwd)
        _check_tenant_configs(login_session, avi_controller_vip)
        login_session.close()

