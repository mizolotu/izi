import json, argparse

from common.docker import exec_cmd_on_container, kill_process_on_container

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Generate traffic.')
    parser.add_argument('-v', '--vms', help='File with vms', default='logs/vms.json')
    parser.add_argument('-c', '--containers', help='File with containers', default='logs/containers.json')
    parser.add_argument('-s', '--scenario', help='File with traffic scenario', default='scenarios/traffic/test1.json')
    args = parser.parse_args()

    with open(args.vms, 'r') as f:
        vms = json.load(f)

    with open(args.containers, 'r') as f:
        containers = json.load(f)

    with open(args.scenario, 'r') as f:
        traffic = json.load(f)

    for item in traffic:
        if 'server' in item.keys():
            c_name = item['name']
            c_vm_name = [container['vm'] for container in containers if container['name'] == c_name]
            assert len(c_vm_name) == 1
            c_vm_name = c_vm_name[0]
            c_vm = [vm for vm in vms if vm['vm'] == c_vm_name]
            assert len(c_vm) == 1
            c_vm = c_vm[0]
            kill_process_on_container(c_vm, c_name, 'python3')