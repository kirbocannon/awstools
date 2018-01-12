# Description
This script assigns a secondary private ip address to an eni and creates and associates a public ip address with that private ip
This script can also list private/public ip associated with the specified interface
Finally, this script can release a private ip from an eni, and release public ip from vpc 

# Compatibility
Python 3+ Only

# Arguments
--vpc-name = Name of the VPC to work on  
--action = Specify if this is an allocate, list, or release operation  
--instance-name = Name of the instance to work on  
--eth-number = Name of the eni to work on  
--private-ip = Specify the private IP address bound to the eni to be unallocated. Will also unallocate the associated public address  
--release-public = Use this switch if you would like to release the elastic IP back to amazon    

# Example Usage:

### List ip addresses associated with eth1 on an instance
python3 ip_allocator.py --vpc-name OAE --instance-name SOAE00LB13-ACT --eth-number 1 --action list

### Allocate private ip on eth1 interface. Create and associate an elastic ip address
python3 ip_allocator.py --vpc-name OAE --instance-name SOAE00LB13-ACT --eth-number 1 --action allocate

### Unassign specified private ip address from eth1 interface. Also release the elastic ip address associated with the private ip
python3 ip_allocator.py --vpc-name OAE --instance-name SOAE00LB13-ACT --eth-number 1 --action release --private-ip 10.33.65.99 --release-public

### Unassign specified private ip address from eth1 interface. Do not release the elastic ip address associated with the private ip
python3 ip_allocator.py --vpc-name OAE --instance-name SOAE00LB13-ACT --eth-number 1 --action release --private-ip 10.33.65.99
