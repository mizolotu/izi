import requests, json, argparse

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

    mon_vms = [vm for vm in vms if vm['vm'] == 'mon']
    assert len(mon_vms) == 1
    mon_vm = mon_vms[0]
    mon_ip = mon_vm['ip']

    attacker_ips = []
    for container in containers:
        if 'attacker' in container['name']:
            attacker_ips.append(container['ip'])

    requests.post('http://{0}:5000/attackers'.format(mon_ip), json={'attackers': attacker_ips})