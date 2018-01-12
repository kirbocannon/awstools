from paramiko import ssh_exception as ssh_err
import paramiko
import time
import argparse
import json
import getpass


def disable_paging(remote_shell):
    '''Disable paging on a Cisco router'''
    remote_shell.send("terminal length 0\n")
    time.sleep(1)
    # Clear the buffer on the screen
    output = remote_shell.recv(1000)
    return output

def calculate_tunnels_and_rd(host, username, private_key=False):
    ''' Instantiate SSHClient object. Disable strict hostkey checking. Invoke the shell.
        Run the command provided and receive the output. '''
    commands = "show ip int br \n show ip bgp all \n"
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    results = dict()
    try:
        if private_key:
            private_key = paramiko.RSAKey.from_private_key_file(private_key)
            ssh.connect(host, username=username, look_for_keys=False,
                        allow_agent=False, timeout=5, pkey=private_key)
        else:
            password = getpass.getpass("Router Password: ")
            ssh.connect(host, username=username, password=password, look_for_keys=False,
                        allow_agent=False, timeout=5)
        print("\n--> SSH connection established to {0}\n".format(host))
        remote_shell = ssh.invoke_shell() # need shell for cisco devices
        disable_paging(remote_shell)
        # send enter key
        remote_shell.send("\n")
        # send command + enter key
        remote_shell.send(commands)
        # Wait for the command to complete
        time.sleep(2)
        output = remote_shell.recv(65535).decode("utf-8").split()
        # Look for interfaces with the name 'Tunnel'
        current_tun_nums = [int(line.split('Tunnel')[1]) for line in output if 'Tunnel' in line]
        # if vpn tunnels are present, calculate next tunnel nums to use. If not, start at tunnel0
        if len(current_tun_nums) > 1:
            # look for tunnel numbers higher than 2000 and remove from list
            for num in current_tun_nums:
                if num > 2000:
                    current_tun_nums.remove(num)
            new_tun_num_one = max(current_tun_nums) + 1
            new_tun_num_two = max(current_tun_nums) + 2
        else:
            new_tun_num_one = 0
            new_tun_num_two = 1
        # look for route discriminator 1:XX
        current_rd_nums = [int(line.split(':')[1]) for line in output if '1:' in line]
        # if rd are present, calculate next rd to use. If not, start at 1:1
        if len(current_rd_nums) != 0:
            # look for rd numbers higher than 2000 and remove from list
            for num in current_rd_nums:
                if num > 2000:
                    current_rd_nums.remove(num)
            new_rd_num = max(current_rd_nums) + 1
        else:
            new_rd_num = '2'
        results['newTunNumOne'] = new_tun_num_one
        results['newTunNumTwo'] = new_tun_num_two
        results['newRdNum'] = new_rd_num
        print('\nNew Tunnels and the Route Distiguiser:\n')
        print(json.dumps(results, sort_keys=True, indent=4))
        return results
    except (ssh_err.BadHostKeyException, ssh_err.AuthenticationException,
            ssh_err.SSHException, Exception) as e:
        print("Could not invoke command on remote device because of the following error: {0}".format(e))

def push_config(host, config, private_key=False):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    username = input('Router Username: ')
    try:
        if private_key:
            private_key = paramiko.RSAKey.from_private_key_file(private_key)
            ssh.connect(host, username=username, look_for_keys=False,
                        allow_agent=False, timeout=5, pkey=private_key)
        else:
            password = getpass.getpass("Password: ")
            ssh.connect(host, username=username, password=password, look_for_keys=False,
                        allow_agent=False, timeout=5)
        print("\n--> SSH connection established to {0} and pushing new tunnel config\n".format(host))
        remote_shell = ssh.invoke_shell() # need shell for cisco devices
        disable_paging(remote_shell)
        remote_shell.send("config t" + "\n")
        commands = ''
        for command in commands:
            remote_shell.send(command + "\n")
        output = remote_shell.recv(65535)
        print(output)
    except (ssh_err.BadHostKeyException, ssh_err.AuthenticationException,
            ssh_err.SSHException, Exception) as e:
        print("Could not invoke command on remote device because of the following error: {0}".format(e))
    pass




