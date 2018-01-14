#!/usr/local/bin/python3

# This script will retrieve information from an existing VPN connection in AWS and generate
# Cisco endpoint config. You must specify the VPC name or site code as well as route distinguisher number,
# tunnel 1 number, tunnel 2 number, private ip address of interface to source on each tunnel, and endpoint name.  
# VGW: Refers to AWS Router side
# Developer: Kenneth Buchanan


from string import Template
import json
import boto3
import argparse
import botocore.endpoint
from botocore.exceptions import ClientError, ParamValidationError
import xml.etree.ElementTree as ET
import ciscoapi as api
import sshvpncommands as ssh


# set args for script
parser = argparse.ArgumentParser()
parser.add_argument('--vpc-name', dest='vpc_name', type =str, help='Specify VPC Name (Site Code)', 
                    required=True)
parser.add_argument('--vpn-name', dest='vpn_name', type=str, help='Name of existing VPN Connection to use', 
                    required=True)
parser.add_argument('--remote-as', dest='remote_as', type=int, help="Remote BGP AS Number. This is Amazon's BGP ASN", 
                    required=True)
parser.add_argument('--host-ip', dest='host_ip', type=str, help="IP Address of the target CSR", 
                    required=True)
parser.add_argument('--prepend-asn', dest='prepend_asn', action='store_true', help="Specify this option if you would like to Prepend the ASN for a less desirable route. This is done on the 'B' side of routers.", 
                    required=False)
parser.add_argument('--push-config', dest='push_config', action='store_true', help="Push the generated configuration to the router immediately.", 
                    required=False)
args = parser.parse_args()

# set base config file and new config file based on user choice of endpoint name
base_cfg_filename = "RXXX00XXXX-AWS-CSR-BASE-CFG.txt"
new_cfg_filename = "{}-AWS-CSR-CFG-CONVERTED.txt".format(args.vpn_name.upper())

def generate_cfg(vpc_name, vpn_name, tun_one_id, tun_two_id, rd_num, remote_as, base_cfg_filename, new_cfg_filename, prepend_asn=False):
    vars = dict()
    try: 
        ec2_session = boto3.session.Session(profile_name=vpc_name)
        ec2 = ec2_session.client(service_name='ec2')
        # Set the filter based on which endpoint the user would like to configure
        vpn_filter = [{'Name': 'tag:Name', 'Values': [vpn_name]}] 
        vpn = ec2.describe_vpn_connections(Filters=vpn_filter)
        cust_cfg = vpn['VpnConnections'][0]['CustomerGatewayConfiguration']
        # parse customer config xml received from aws
        vpn_config_xml = ET.fromstring(cust_cfg) 
        # set site code, tunnel ids, route distingusher
        vars['vpcName'] = vpc_name
        vars['tunOneId'] = tun_one_id
        vars['tunTwoId'] = tun_two_id
        vars['rdNum'] = rd_num
        vars['remoteAs'] = remote_as
        # get our BGP ASN that we specified when creating the customer gateway. This should be the same for both tunnels
        vars['bgpAsn'] = vpn_config_xml[3][0][2][0].text 
        # get private tunnel 1 address of AWS VGW (bgp neighbor of our vpn_name)
        vars['tunOneBgpNeighborIp'] = vpn_config_xml[3][1][1][0].text 
        # get private tunnel 2 address of AWS VGW (bgp neighbor of our vpn_name)
        vars['tunTwoBgpNeighborIp'] = vpn_config_xml[4][1][1][0].text 
        # get private tunnel 1 address for our endpoint router
        vars['tunOneIntIp'] = vpn_config_xml[3][0][1][0].text 
        # get private tunnel 2 address for our endpoint router
        vars['tunTwoIntIp'] = vpn_config_xml[4][0][1][0].text 
        # get public destination ip address of AWS VGW for tunnel 1 on our vpn_name
        vars['tunOneDestIp'] = vpn_config_xml[3][1][0][0].text
        # get public destination ip address of AWS VGW for tunnel 2 on our endpoint
        vars['tunTwoDestIp'] = vpn_config_xml[4][1][0][0].text 
        # get pre-shared key for vpn tun 1 public destination ip address of AWS VGW 
        vars['tunOnePreKey'] = vpn_config_xml[3][2][5].text  
        # get pre-shared key for vpn tun 2 public destination ip address of AWS VGW 
        vars['tunTwoPreKey'] = vpn_config_xml[4][2][5].text
        #print(cust_cfg)
        #parse config file
        with open(base_cfg_filename, 'r') as f:
            data = f.read()
        with open(new_cfg_filename, encoding='utf-8', mode='w+') as f:
            # Check to see if user has added the asn prepend option. If so, add appropriate route map
            if prepend_asn:
                vars['prependAsnOne'] = "neighbor {} route-map RM_TO_SPOKE_VPCS out".format(vars['tunOneBgpNeighborIp'])
                vars['prependAsnTwo'] = "neighbor {} route-map RM_TO_SPOKE_VPCS out".format(vars['tunTwoBgpNeighborIp'])
            else:
                vars['prependAsnOne'] = '!'
                vars['prependAsnTwo'] = '!'
            f.write(Template(data).safe_substitute(vars))
        print("\nVPN configuration for {} complete! Here are the variables used:\n".format(args.vpn_name))
        print(json.dumps(vars, sort_keys=True, indent=4))
        return vars
    except(ClientError, ParamValidationError, OSError, IndexError) as e:
        print("I wasn't able to finish creating the VPN config file. See message below:")
        print(e)
        print("Check to see that your resource-name is correct and you have access to AWS API")

if __name__ == '__main__':
    # specify csr ip
    host_ip = api.host_ip(args.host_ip)
    # Log into router and calculate tunnels to use
    token = api.create_token()
    # if we were able to get the token
    if token:
        # get the interfaces 
        # host_ip = '10.44.79.74'
        interfaces = api.get_tunnel_interfaces(token=token)
        # calculate the tunnels to use
        new_tunnels = api.calculate_tunnels(interfaces)
        # get route distinguisers  
        rds = api.get_rds(token)
        # calculate new route distinguisers 
        new_rd = api.calculate_rd(rds)
        # generate vpn config and save it to a configuraiton file
        generate_cfg(
            vpc_name=args.vpc_name.upper(),
            vpn_name=args.vpn_name.upper(),
            remote_as=args.remote_as,
            tun_one_id=str(new_tunnels['newTunNumOne']),
            tun_two_id=str(new_tunnels['newTunNumTwo']),
            rd_num=str(new_rd['newRdNum']),
            base_cfg_filename=base_cfg_filename, 
            new_cfg_filename=new_cfg_filename,
            prepend_asn=args.prepend_asn
            )
        # if user specifies the --push-config option
        #if args.push_config:
            # read newly generated configuration file
    #     with open(new_cfg_filename, encoding='utf-8', mode='r') as f:
    #         commands = f.readlines()
    #         config = ''.join(commands)
            # push configuration
            #config_push_resp = api.push_config(token=token, config=config)
    else:
        print("\nUnable to get token. Check username/password or connection.")




