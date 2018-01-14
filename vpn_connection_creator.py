#!/usr/local/bin/python3

# This script will create a customer gateway and VPN connection and associate with the customer gateway
# The user must specify vpc name, bgp asn, public IP of destination VPN device, and name of that device
# Note that for static VPNs, the static route will automatically propagate to the route tables for VPC 
# when VPN tunnel is up but you must enable route propagation on the route table first
# Developer: Kenneth Buchanan


# add route map for all vrf bgp neighbors 

import boto3
import argparse
import botocore.endpoint
from botocore.exceptions import ClientError, ParamValidationError

# Create main parser
parser = argparse.ArgumentParser(prog='vpn_connection_creator')
# Create global arguments
parser.add_argument('--vpc-name', dest='vpc_name', type =str, help='Specify VPC name for VPN connection', 
                    required=True)
parser.add_argument('--action', action='store_true', help='Specify Action', required=True)
# Create subparser, store subparser name selected for later logic
subparsers = parser.add_subparsers(help='sub-command help', dest='subparser_name')
# Create vpn list subparser and associated arguments
parser_vpn_list = subparsers.add_parser('list', help='List all VPNs in a given VPC')
parser_vpn_list.add_argument('--filter', type=str, help='Only list VPNs which meet filter criteria', required=False)
# Create vpn create subparser and associated arguments
parser_vpn_create = subparsers.add_parser('create', help='Create a VPN Connection')
parser_vpn_create.add_argument('--vpn-name', dest='vpn_name', type=str, help='Name tag of VPN Connection', 
                    required=True)
parser_vpn_create.add_argument('--cg-name', dest='cg_name', type=str, help=' Name tag of Customer Gateway', 
                    required=True)
parser_vpn_create.add_argument('--public-ip', dest='public_ip', type=str, help='Public IP of destination VPN device', 
                    required=True)
parser_vpn_create.add_argument('--bgp-asn', dest='bgp_asn', default=65000, type =int, help='BGP ASN for VPN connection', 
                    required=False)
parser_vpn_create.add_argument('--static', dest='static', type=str, default='None',
                               help='CIDR Block to advertise to local VPN. For example: 0.0.0.0/0 advertises a static default route to the VPC',
                               required=False)
# Create vpn delete subparser and associated arguments
parser_vpn_delete = subparsers.add_parser('delete', help='Delete a VPN Connection')
parser_vpn_delete.add_argument('--vpn-name', dest='vpn_name', type=str, help='Name of VPN connection to delete', 
                    required=True)
parser_vpn_delete.add_argument('--no-prompt', dest='no_prompt_selected', action='store_true', help='No Prompt when you delete the VPN connection', 
                    required=False)
args = parser.parse_args()

def create_vpn_conn(vpc_name, public_ip, bgp_asn, cg_name, vpn_name, static=None):
    # Set default static routing to False. Check if user specified the static arg
    static_only = False
    if static != 'None':
        static_only = True
    try:
        # Create customer gateway 
        customer_gateway = ec2.create_customer_gateway(
            Type='ipsec.1',
            PublicIp=public_ip,
            BgpAsn=bgp_asn
        )
        # get customer gateway Id
        customer_gw_id = customer_gateway['CustomerGateway']['CustomerGatewayId']
        # Set filter and get VPC Id
        vpn_filter = [{'Name': 'tag:Name', 'Values': ["*{}*".format(vpc_name)]}]
        vpn_gw = ec2.describe_vpn_gateways(Filters=vpn_filter)
        vpn_gw_id = vpn_gw['VpnGateways'][0]['VpnGatewayId']
        # Create VPN connection
        vpn_connection = ec2.create_vpn_connection(
            Type='ipsec.1',
            CustomerGatewayId=customer_gw_id,
            VpnGatewayId=vpn_gw_id,
            Options={
                'StaticRoutesOnly': static_only
            }
        )
        vpn_connection_id = vpn_connection['VpnConnection']['VpnConnectionId']
        # Tag resources 
        ec2.create_tags(
            Resources=[customer_gw_id],
            Tags=[{'Key': 'Name','Value': cg_name}]
            )
        ec2.create_tags(
            Resources=[vpn_connection_id],
            Tags=[{'Key': 'Name','Value': vpn_name}]
            )
        # if user specified static arg, create static route specified by user
        if static_only == True:
            vpn_connection_route = ec2.create_vpn_connection_route(
                DestinationCidrBlock=static,
                VpnConnectionId=vpn_connection_id
                )
        print("\nVPN Connection successfully created!")
    except(ClientError, ParamValidationError, BaseException) as e:
        print("I wasn't able to finish creating the VPN connection. See message below:")
        print(e)

def list_vpn_conns(vpc_name, vpn_conn_name='*{}*'.format(args.vpc_name)):
    ''' List all VPN connections associated with the specified VPC site code 
        The default will look for any VPN connection with the specified VPC site code '''
    vpn_cnt = 0
    try:
        vpn_filter = [{'Name': 'tag:Name', 'Values': [vpn_conn_name]}]
        vpns = ec2.describe_vpn_connections(Filters=vpn_filter)
        vpns = vpns['VpnConnections']
        for vpn in vpns:
            # retrieve associated customer gateway name
            cust_gw_id = vpn['CustomerGatewayId']
            cust_gw_filter = [{'Name': 'customer-gateway-id', 'Values': [cust_gw_id]}]
            cust_gw = ec2.describe_customer_gateways(Filters=cust_gw_filter)['CustomerGateways'][0]
            print('---------------------------------------------')
            # generator function to only print the value of the 'Name' tag from the list of tags of the resource
            print('VPN Name:', next((tag['Value'] for tag in vpn['Tags'] if tag['Key'] == 'Name')))
            print('\n')           
            print('Tunnel 1 Details --------')            
            print('State:', vpn['State'])
            print('Status:', vpn['VgwTelemetry'][0]['Status'])
            print('Message:', vpn['VgwTelemetry'][0]['StatusMessage'])
            print('AWS VPN IP:', vpn['VgwTelemetry'][0]['OutsideIpAddress'])
            print('Last Changed:', vpn['VgwTelemetry'][0]['LastStatusChange'])
            print('\n')
            print('Tunnel 2 Details --------')
            print('Status:', vpn['VgwTelemetry'][1]['Status'])
            print('Message:', vpn['VgwTelemetry'][1]['StatusMessage'])
            print('AWS VPN IP:', vpn['VgwTelemetry'][1]['OutsideIpAddress'])
            print('Last Changed:', vpn['VgwTelemetry'][1]['LastStatusChange'])
            print('\n')
            # if there is an associated customer gateway
            if cust_gw:
                print('Customer Gateway Details --------')
                # generator function to only print the value of the 'Name' tag from the list of tags of the resource 
                print('Customer Gateway Name:', next((tag['Value'] for tag in cust_gw['Tags'] if tag['Key'] == 'Name')))
                print('Customer Gateway IP Address:', cust_gw['IpAddress'])
                print('Customer Gateway BGP ASN:', cust_gw['BgpAsn'])
            else:
                print('Could not find an associated customer gateway')
            print('\n')
            print('---------------------------------------------')
            vpn_cnt+=1
        print('\nNumber of VPN Connections Found: {}'.format(vpn_cnt))
    except (ClientError, ParamValidationError, BaseException) as e:
        print(e)
        print("No VPNs could be retreived.")
        
def delete_vpn_conn(vpc_name, vpn_name, no_prompt_selected=False):
    """ User will use --vpn-name argument to specify explicitly which vpn to delete """
    try:
        vpn_filter = [{'Name': 'tag:Name', 'Values': [vpn_name]}]
        vpn = ec2.describe_vpn_connections(Filters=vpn_filter)
        vpn = vpn['VpnConnections'][0]
        vpn_id = vpn['VpnConnectionId']
        customer_gw_id = vpn['CustomerGatewayId']
        vpn_name = next((tag['Value'] for tag in vpn['Tags'] if tag['Key'] == 'Name'))
        if no_prompt_selected:
            print("okay, deleting VPN Connection: {} and associated CG".format(vpn_name))
            delete_vpn_connection = ec2.delete_vpn_connection(
                VpnConnectionId = vpn_id
                )
            delete_customer_gateway = ec2.delete_customer_gateway(
                CustomerGatewayId = customer_gw_id
                )
            print('VPN Connection and associated CG deleted!')
        else:
            answer = input("\nAre you sure you want to delete the following VPN Connection? \n{}. Type 'YES' to delete forever: ".format(vpn_name))
            if answer.upper() == 'YES':
                print("okay, deleting VPN Connection: {} and associated Customer Gateway".format(vpn_name))
                delete_vpn_connection = ec2.delete_vpn_connection(
                    VpnConnectionId = vpn_id
                )
                delete_customer_gateway = ec2.delete_customer_gateway(
                    CustomerGatewayId = customer_gw_id
                    )
                print('VPN Connection and associated Customer Gateway deleted!')
            else:
                print("cancelling operation...")
                exit()
    except (ClientError, ParamValidationError, BaseException) as e:
        print(e)
        print('Unable to delete vpn connection')




if __name__ == '__main__':
    ec2_session = boto3.session.Session(profile_name=args.vpc_name)
    ec2 = ec2_session.client(service_name='ec2')
    # if list subparser is selected
    if args.subparser_name == 'list':
        # describe VPNs with user input if --filter [FILTER] argument is used
        if args.filter:
            list_vpn_conns(vpc_name=args.vpc_name, vpn_conn_name=args.filter)
        else:
            list_vpn_conns(vpc_name=args.vpc_name)
    # if create subparser is selected 
    elif args.subparser_name == 'create':
        create_vpn_conn(vpc_name=args.vpc_name, 
                        public_ip=args.public_ip, 
                        bgp_asn=args.bgp_asn,
                        cg_name=args.cg_name,
                        vpn_name=args.vpn_name,
                        static=args.static
                        )
    elif args.subparser_name == 'delete':
        delete_vpn_conn(vpc_name=args.vpc_name, 
                        vpn_name=args.vpn_name,
                        no_prompt_selected=args.no_prompt_selected
                        )
    



