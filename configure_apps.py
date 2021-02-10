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

    cmds = [
        'service apache2 start',
        'service mysql start',
        'service ssh start',
        'useradd izi',
        'usermod --password $1$GtkMPwwB$u8MfSW50pqROdixJrxxvX. izi',
        'python3 ares.py initdb',
        'python3 ares.py runserver -h 0.0.0.0 -p 8080 --threaded',
        'python3 init_dvwa.py'
    ]
    for item in traffic:
        c_name = item['name']
        c_vm_name = [container['vm'] for container in containers if container['name'] == c_name]
        assert len(c_vm_name) == 1
        c_vm_name = c_vm_name[0]
        c_vm = [vm for vm in vms if vm['vm'] == c_vm_name]
        assert len(c_vm) == 1
        c_vm = c_vm[0]
        print(c_name)
        for cmd in cmds:
            if '-h 0.0.0.0' in cmd:
                detach = True
            else:
                detach = False
            r = exec_cmd_on_container(c_vm, c_name, cmd, detach=detach)
            print(r)