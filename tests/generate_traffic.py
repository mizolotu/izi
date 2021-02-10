import json
import argparse as arp

from common.docker import exec_cmd_on_container, kill_process_on_container

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Generate traffic.')
    parser.add_argument('-v', '--vms', help='File with vms', default='logs/vms.json')
    parser.add_argument('-c', '--containers', help='Network scenario', default='logs/containers.json')
    parser.add_argument('-t', '--traffic', help='Traffic scenario', default='scenarios/traffic/test1.json')
    parser.add_argument('-d', '--duration', help='Duration', default=60, type=int)
    args = parser.parse_args()

    vms = args.vms
    containers = args.containers
    traffic = args.traffic
    dur = args.duration

    with open(vms, 'r') as f:
        vms = json.load(f)

    with open(traffic, 'r') as f:
        traffic = json.load(f)

    with open(containers, 'r') as f:
        containers = json.load(f)

    iptables_cmd = 'iptables -A OUTPUT -p tcp -o eth0 --tcp-flags RST RST -j DROP'

    for item in traffic:
        if item['type'] == 'server':
            c_name = item['name']
            c_vm_name = [container['vm'] for container in containers if container['name'] == c_name]
            assert len(c_vm_name) == 1
            c_vm_name = c_vm_name[0]
            c_vm = [vm for vm in vms if vm['vm'] == c_vm_name]
            assert len(c_vm) == 1
            c_vm = c_vm[0]
            cmd = 'python3 server.py -t {0}'.format(item['label'])
            kill_process_on_container(c_vm, c_name, 'python3')
            exec_cmd_on_container(c_vm, c_name, iptables_cmd)
            exec_cmd_on_container(c_vm, c_name, cmd)

    for item in traffic:
        if item['type'] == 'client':
            c_name = item['name']
            c_vm_name = [container['vm'] for container in containers if container['name'] == c_name]
            assert len(c_vm_name) == 1
            c_vm_name = c_vm_name[0]
            c_vm = [vm for vm in vms if vm['vm'] == c_vm_name]
            assert len(c_vm) == 1
            c_vm = c_vm[0]
            cmd = 'python3 client.py -t {0} -r {1}'.format(item['label'], item['server'])
            kill_process_on_container(c_vm, c_name, 'python3')
            exec_cmd_on_container(c_vm, c_name, iptables_cmd)
            exec_cmd_on_container(c_vm, c_name, cmd)




