import json, requests
import argparse as arp

from common.docker import *

def main(_vms, _scenario, _image, _containers):

    # read logs

    with open(_vms, 'r') as f:
        vms = json.load(f)

    with open(_scenario, 'r') as f:
        containers = json.load(f)

    # container commands

    cmds = [
        'ifconfig eth0 mtu 1450',
        'service apache2 start',
        'service mysql start',
        'service ssh start',
        'useradd izi',
        'usermod --password $1$GtkMPwwB$u8MfSW50pqROdixJrxxvX. izi',
        'python3 ares.py initdb',
        'python3 ares.py runserver -h 0.0.0.0 -p 8080 --threaded',
        'python3 init_dvwa.py'
    ]

    # create containers

    c_vm_names = list(set([container['vm'] for container in containers]))
    for c_vm_name in c_vm_names:

        c_vm = [vm for vm in vms if vm['vm'] == c_vm_name]
        assert len(c_vm) == 1
        c_vm = c_vm[0]

        # pull image

        print(c_vm['vm'], _image)
        #pull_image(c_vm['ip'], _image)

        # remove existing containers

        remove_containers(c_vm['ip'])

        # create netns directory

        create_netns_dir(c_vm)

        # create containers, connect them to the corresponding bridges and execute initial commands

        for container in containers:
            if container['vm'] == c_vm['vm']:

                ofport = run_container(c_vm, container['name'], _image, container['ip'])
                container['ofport'] = ofport

                for cmd in cmds:
                    if '-h 0.0.0.0' in cmd:
                        detach = True
                    else:
                        detach = False
                    r = exec_cmd_on_container(c_vm, container['name'], cmd, detach=detach)
                    print(container['name'], r)

    with open(_containers, 'w') as f:
        json.dump(containers, f)

    # send information about malicious applications to the monitor

    mon_vms = [vm for vm in vms if vm['vm'] == 'mon']
    assert len(mon_vms) == 1
    mon_vm = mon_vms[0]
    mon_ip = mon_vm['ip']

    attacker_ips = []
    for container in containers:
        if 'attacker' in container['name']:
            attacker_ips.append(container['ip'])

    requests.post('http://{0}:5000/attackers'.format(mon_ip), json={'attackers': attacker_ips})

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Create networks')
    parser.add_argument('-s', '--scenario', help='File with containers', default='scenarios/network/test1.json')
    parser.add_argument('-i', '--image', help='Docker image to use', default='ntizi/traffic-generator:latest')
    parser.add_argument('-v', '--vms', help='File with vms', default='logs/vms.json')
    parser.add_argument('-c', '--containers', help='File with containers', default='logs/containers.json')
    args = parser.parse_args()

    main(args.vms, args.scenario, args.image, args.containers)







