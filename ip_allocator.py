# This script assigns a secondary private ip address to an eni and creates and associates a public ip address with that private ip
# This script can also list private/public ip associated with the specified interface
# Finally, this script can release a private ip from an eni, and release public ip from vpc
# Example ussage:
# python ip_allocator.py --vpc-name OAE --instance-name SOAE00LB13-ACT --eth-number 1 --action list

import boto3
import argparse
import botocore.endpoint
from botocore.exceptions import ClientError, ParamValidationError
import ipaddress

# Create main parser
parser = argparse.ArgumentParser(prog='ip_allocator')
# Create global arguments
parser.add_argument('--vpc-name', dest='vpc_name', type =str, help='Specify VPC site code to run this script against', 
                    required=True)
parser.add_argument('--instance-name', dest='instance_name', type =str, help='Specify Instance name tag', 
                    required=True)
parser.add_argument('--eth-number', dest='eth_number', type =int, help='Specify ethernet number. For example, enter 1 for eth1', 
                    required=True)
parser.add_argument('--action', action='store_true', help='Specify Action', required=True)
# Create subparser, store subparser name selected for later logic
subparsers = parser.add_subparsers(help='sub-command help', dest='subparser_name')
# Create IP address list subparser and associated arguments
parser_list_ips = subparsers.add_parser('list', help='List all IPs associated with the ENI')
parser_allocate_ip = subparsers.add_parser('allocate', help='List all IPs associated with the ENI')
parser_release_ip = subparsers.add_parser('release', help='release specified private ip from the interface')
parser_release_ip.add_argument('--private-ip', dest='private_ip', type =str, help='Specify Private IP to unassign', 
                    required=True)
parser_release_ip.add_argument('--release-public', action='store_true', dest='release_public_ip', help='Specify this argument to release the public ip address as well', required=False)
args = parser.parse_args()

# Proxy server for calling out to AWS 
proxy_server = 'proxy-ftc.ad.moodys.net'
# Set proxy using monkey patching here. There's no easy way to set proxy in boto3 besides environment
# variables, which may be too envasive 
def _get_proxies(self, url):
    return {'http': proxy_server, 'https': proxy_server}

def calculate_private_ip(cidr, used_ips):
    """ Determines which IP address to assign by describing in-use ENI private IPs and comparing to available host ips in subnet.
        Also removes reserved amazon addresses from list of host addresses

        Reserved Amazon Addresses, we are using 10.0.0.0/24 subnet as an example:

        10.0.0.1: Reserved by AWS for the VPC router.
        10.0.0.2: Reserved by AWS. The IP address of the DNS server is always the base of the VPC network range plus two; 
                  however, we also reserve the base of each subnet range plus two. 
        10.0.0.3: Reserved by AWS for future use.

        """
    try:
        # aws reserved router address
        aws_router_ip = ipaddress.ip_network(cidr).network_address + 1
        # aws reserved dhcp server address
        aws_dhcp_server_ip = ipaddress.ip_network(cidr).network_address + 2
        # aws reserved 'for future use' address
        aws_reserved_ip = ipaddress.ip_network(cidr).network_address + 3
        # Create a list of host addresses within the subnet range, remove those hosts from host ips list
        host_ips = list(ipaddress.ip_network(cidr).hosts())
        host_ips.remove(aws_router_ip)
        host_ips.remove(aws_dhcp_server_ip)
        host_ips.remove(aws_reserved_ip)
        host_ips = [ip.exploded for ip in host_ips]
        # compare sets and remove ip addresses that appear in both sets (already used ips)
        available_ips = list(set(host_ips) - set(used_ips))
        cnt = 0
        for ip in available_ips:
            #print(ip)
            cnt+=1
        if cnt > 0:
            new_ip = available_ips[0]
            #print("Assigining {}".format(new_ip))
        else:
            print('No Available IPs to allocate. Exiting...')
            quit()
        print("--> Amount of avaialble IPs in the eni's subnet: {}".format(cnt))
        return new_ip
    except (ClientError, ParamValidationError, BaseException) as e:
        print("Couldn't calculate an ip address to use. See error below:")
        print(e)

def describe_instance(instance_name, eth_number):
    """ get instance/eni info and return dictionary of that info """
    instance_attribs = dict()
    eni_cnt = 0
    try:
        # filter instance based on name tag provided by user
        instance_filter = [{'Name': 'tag:Name', 'Values': [instance_name]}]
        instance = ec2.describe_instances(Filters=instance_filter)
        instance_enis = instance['Reservations'][0]['Instances'][0]['NetworkInterfaces']
        # generator function to search and return only eni1 attributes on the appliance 
        eni = next(eni for eni in instance_enis if eni['Attachment']['DeviceIndex'] == eth_number)
        eni_interface_id = eni['NetworkInterfaceId']
        eni_subnet_id = eni['SubnetId']
        # subnet filter used to get cidr
        subnet_filter = [{'Name': 'subnet-id', 'Values': [eni_subnet_id]}]
        # generator function to search and return only eth1 private/public IP addresses on the appliance
        eni_ips = next(eni['PrivateIpAddresses'] for eni in instance_enis if eni['Attachment']['DeviceIndex'] == eth_number)
        # Keep count of the number of eni ips for eni2 (eth1)
        for ip in eni_ips:
            eni_cnt+=1
        # get subnet CIDR
        subnet = ec2.describe_subnets(Filters=subnet_filter)
        subnet_cidr = subnet['Subnets'][0]['CidrBlock']
        #instance_attribs['eni'] = eni
        # add attributes to a dictionary to use later in other functions
        instance_attribs['instance_name'] = instance_name
        instance_attribs['eth_number'] = eth_number
        instance_attribs['eni_interface_id'] = eni_interface_id
        instance_attribs['eni_ips'] = eni_ips
        instance_attribs['eni_cnt'] = eni_cnt
        instance_attribs['eni_subnet_id'] = eni_subnet_id
        instance_attribs['subnet_cidr'] = subnet_cidr
        return instance_attribs     
    except (ClientError, ParamValidationError, BaseException) as e:
        print("Couldn't get information from instance. See error below:")
        print(e)

def print_assoc_ips(instance):
    """ Print all IP addresses associated with eth1 """
    try:
        print("\n")
        print("------------------------------------------------------------------")
        for ip in instance['eni_ips']:
            private_ip = ip['PrivateIpAddress']
            # try/except clauses are used here because sometimes the public IP address may not be assigned
            try:
                public_ip = ip['Association']['PublicIp']
            except KeyError:
                public_ip = "Not Assigned"
            print("| Private IP: {0:16}".format(private_ip), "--->  ", "Public IP: {0:16}|".format(public_ip))
            print("------------------------------------------------------------------")
        print("\nNumber of IP addresses assigned to {}: {}".format(instance['eni_interface_id'], instance['eni_cnt']))
    except (ClientError, ParamValidationError, BaseException) as e:
        print("Couldn't get ENI information See error below:")
        print(e)

def allocate_ip(instance):
    """ Creates both public and private IP addresses and then associates public the two"""
    subnet_id_filter = [{'Name': 'subnet-id', 'Values': [instance['eni_subnet_id']]}]
    used_ips = list()
    try:
        # Look for all network interfaces in same subnet as instance eth1 interface
        interfaces = ec2.describe_network_interfaces(Filters=subnet_id_filter)
        interfaces = interfaces['NetworkInterfaces']
        for interface in interfaces:
            # iterate through each private ip address associated with each interface
            private_ip_addresses_list = interface['PrivateIpAddresses']
            #print(interface['NetworkInterfaceId'])
            for private_ip in private_ip_addresses_list:
                used_ip = private_ip['PrivateIpAddress']
                used_ips.append(used_ip)
        print("\n")
        new_private_ip = calculate_private_ip(instance['subnet_cidr'], used_ips)
        print("--> Assigining private IP {} to {}'s {} network interface".format(new_private_ip, instance['instance_name'], instance['eni_interface_id'] ))
        # assign new private ip address calculated with the 'calculate_private_ip' function
        assign_private_ip = ec2.assign_private_ip_addresses(
            AllowReassignment=False,
            NetworkInterfaceId=instance['eni_interface_id'],
            PrivateIpAddresses=[new_private_ip]
        )
        print("--> Creating public ip")
        # allocate a new public ip address for the VPC
        allocate_public_ip = ec2.allocate_address(Domain='vpc')
        new_public_ip = allocate_public_ip['PublicIp']
        new_public_allocation_id = allocate_public_ip['AllocationId']
        print("--> Public ip {} created".format(new_public_ip))
        # associate the public ip address with the private ip address on the eni
        ec2.associate_address(
            AllocationId=new_public_allocation_id,
            AllowReassociation=False,
            NetworkInterfaceId=instance['eni_interface_id'],
            PrivateIpAddress=new_private_ip
        )
        print("--> Private ip {} was associated with public ip {}".format(new_private_ip, new_public_ip))
        print("--> The new association may take a moment to reflect on aws")
    except (ClientError, ParamValidationError, BaseException) as e:
        print("Couldn't assign IPs to the ENI. See error below:")
        print(e)

def release_ip(instance, private_ip, release_public_ip=False):
    """ unassigns private ip from the eni """
    # release private ip address from eni
    print("Removing {} from eth{}".format(private_ip, instance['eth_number']))
    ec2.unassign_private_ip_addresses(
        NetworkInterfaceId=instance['eni_interface_id'],
        PrivateIpAddresses=[
            private_ip,
        ]
    )
    # Release public ip if user specifies the --release-public switch
    if release_public_ip:
        try:
            print("--> Releasing public ip address")
            for ip in instance['eni_ips']:
                if private_ip == ip['PrivateIpAddress']:
                    public_ip = ip['Association']['PublicIp']
                    public_ip_filter = [{'Name': 'public-ip', 'Values': [public_ip]}]
                    describe_public_ip = ec2.describe_addresses(Filters=public_ip_filter,
                        PublicIps=[
                            public_ip,
                        ]
                    )
                    public_ip_allocation_id = describe_public_ip['Addresses'][0]['AllocationId']
                    ec2.release_address(AllocationId=public_ip_allocation_id)
        except (ClientError, ParamValidationError, BaseException) as e:
            print("An error occured. Did you specify the correct private ip address?")
            print(e)

         

if __name__ == '__main__':
    # set moody's proxy
    botocore.endpoint.EndpointCreator._get_proxies = _get_proxies
    ec2_session = boto3.session.Session(profile_name=args.vpc_name)
    ec2 = ec2_session.client(service_name='ec2')
    instance = describe_instance(instance_name=args.instance_name, eth_number=args.eth_number)
    # if list subparser is selected
    if args.subparser_name == 'list':
        print_assoc_ips(instance)
    elif args.subparser_name == 'allocate':
        allocate_ip(instance)
    elif args.subparser_name == 'release':
        if args.release_public_ip:
            release_ip(instance, args.private_ip, release_public_ip=True)
        else:
            release_ip(instance, args.private_ip)