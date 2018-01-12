import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from requests.adapters import HTTPAdapter
import json
import sys
import getpass

# disable insecure warnings
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

base_url = 'https://{}:55443/api/v1/{}'

# header info
headers = {
    'User-Agent': 'cisco_api_python_script', 
           }

json_formated = {'Accept': 'application/json'}
text_formated = {'Accept': 'text/plain'}
host_ip_lst = []

# supported api calls and their properties
# url = url for api
# method = method type to use for this call
# content_type = content type to receive from api response
# basic_auth = False will use basic credentials. True will use temporary token
# payload = commands to send to device
apis = {
    'create_temp_token': {
        'url': 'auth/token-services',
        'method': 'POST',
        'content_type': json_formated,
        'basic_auth': True
        },
    'get_tunnel_interfaces': {
        'url': 'interfaces',
        'method': 'GET',
        'content_type': json_formated,
        'basic_auth': False
        },
    'get_rds': {
        'url': 'global/cli',
        'method': 'PUT',
        'content_type': json_formated,
        'basic_auth': False,
        'payload': {'show': 'ip bgp all | i Distinguisher'}
        },
    'push_config': {
        'url': 'global/cli',
        'method': 'PUT',
        'content_type': json_formated,
        'basic_auth': False,
        'payload': {'config': ""}
        },
    }

def host_ip(host_ip):
    """ Updates the csr ip list """
    host_ip_lst.append(host_ip)

def build_request(req, host_ip=host_ip_lst, headers=headers, config=None, token=False, payload=None):
    """ Build REST API request to cisco CSR """
    # amount of retries to attempt
    retries = 3
    host_ip = host_ip[0] # get first and only csr in list
    auth = req.get('basic_auth', False)
    headers.update(req['content_type'])
    api_url = base_url.format(host_ip, req['url'])
    try:
        # retry specified number of times
        s = requests.Session()
        s.mount('http://', HTTPAdapter(max_retries=retries))
        # if api call requires basic auth
        if auth:
            username = input('Username: ')
            password = getpass.getpass('Password: ')
            auth = (username, password)
        # if a temporary token was passed
        if token:
            headers['X-auth-token'] = token
        # if there is custom configuration the user want's to push, update the data field 
        if config:
            apis['push_config']['payload']['config'] = config
        # if api call requires GET method
        if req['method'] == 'GET':
            response = requests.get(api_url, headers=headers, auth=auth, verify=False)
        # if api call requires PUT method
        if req['method'] == 'PUT':
            response = requests.put(api_url, headers=headers, auth=auth, json=payload, verify=False)
        # if api call requires POST method
        if req['method'] == 'POST':
            response = requests.post(api_url, headers=headers, auth=auth, verify=False)
        print("\n--> Calling API at: {}".format(api_url))
        print("\nAPI Response:\n")
        print(response)
        return response
    except requests.exceptions.RequestException as e:  
        print(e)
        sys.exit(1)

def create_token():
    try:
        """ Create temporary token and store for this session """
        # update csr ip
        response = build_request(apis['create_temp_token'], headers=headers)
        response = response.json()
        token = response['token-id']
        expire_time = response['expiry-time']
        print('Temporary Token:', token)
        print('Expires:', expire_time)
        return token
    except:
        print('\nUnable To get token')

def get_tunnel_interfaces(token):
    """ Get all l3 interfaces on the csr """
    interfaces = build_request(apis['get_tunnel_interfaces'], headers=headers, token=token)
    interfaces = interfaces.json()
    interfaces = interfaces['items']
    return interfaces

def get_rds(token):
    """ Get current Route Distinguisers """
    rds = build_request(apis['get_rds'], headers=headers, token=token, payload=apis['get_rds']['payload'])
    rds = rds.json()
    rds = rds['results']
    return rds

def push_config(token, config):
    push_config = build_request(apis['push_config'], headers=headers, token=token, config=config, payload=apis['push_config']['payload'])
    return push_config

def calculate_tunnels(interfaces):
    """ Calculate two new tunnels. Rule is to increment the highest tunnel number by 1, and 2, unless above 2000"""
    new_tunnels = dict()
    current_tunnels = [int(interface['if-name'].split('Tunnel')[1]) for interface in interfaces if 'Tunnel' in interface['if-name']]
    # if vpn tunnels are present, calculate next tunnel nums to use. If not, start at tunnel0
    if len(current_tunnels) != 0:
        # look for tunnel numbers higher than 2000 because these are assigned for other functions. Remove from list
        for num in current_tunnels:
            if num > 2000:
                current_tunnels.remove(num)
        new_tun_num_one = max(current_tunnels) + 1
        new_tun_num_two = max(current_tunnels) + 2
    else:
        new_tun_num_one = 0
        new_tun_num_two = 1
    new_tunnels['newTunNumOne'] = new_tun_num_one
    new_tunnels['newTunNumTwo'] = new_tun_num_two
    return new_tunnels

def calculate_rd(rds):
    """ Calculate the next route distinguiser number to use """
    new_rd = dict()
    current_rd_nums = [int(line.split(':')[1]) for line in rds.split() if '1:' in line]
    if len(current_rd_nums) != 0:
        # look for rd numbers higher than 2000 and remove from list
        for num in current_rd_nums:
            if num > 2000:
                current_rd_nums.remove(num)
        new_rd_num = max(current_rd_nums) + 1
    else:
        new_rd_num = '2'
    new_rd['newRdNum'] = new_rd_num
    return new_rd



"""
# Create the token
token = create_token()
# get the interfaces 
interfaces = get_tunnel_interfaces(token)
# calculate the tunnels to use
new_tunnels = calculate_tunnels(interfaces)
# route distriguistiors 
rds = get_rds(token)
new_rds = calculate_rd(rds)
print(new_tunnels)
print(new_rds)
"""

# backup running-config 
#running_config = "https://{}:55443/api/v1/global/running-config".format(host_ip)
#headers.update(text_formated)
#running_config = requests.get(running_config, headers=headers, verify=False)
#running_config = running_config.text
#with open(host_ip + '-' + 'backup.txt', 'w+') as f:
#    f.write(running_config)













