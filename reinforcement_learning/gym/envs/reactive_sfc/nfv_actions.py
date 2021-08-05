import json, requests

from config import *
from time import sleep

def reset_ids(ids_ip, ids_port, sleep_interval=0.1):
    uri = f'http://{ids_ip}:{ids_port}/reset'
    ready = False
    while not ready:
        try:
            requests.get(uri)
            ready = True
        except:
            sleep(sleep_interval)

def set_vnf_param(ids_ip, ids_port, param, value):
    uri = f'http://{ids_ip}:{ids_port}/{param}'
    r = requests.post(uri, json={param: value})
    value = r.json()[param]
    return value

if __name__ == '__main__':

    # load data

    with open(vms_fpath, 'r') as f:
        vms = json.load(f)

    with open(nodes_fpath, 'r') as f:
        nodes = json.load(f)

    with open(tunnels_fpath, 'r') as f:
        tunnels = json.load(f)

    # ids vms

    ids_vms = [vm for vm in vms if vm['role'] == 'ids']
    ids_nodes = [nodes[vm['vm']] for vm in ids_vms]
    assert (len(ids_nodes) + 5) <= ntables

    # set param values

    values = [9,3]

    for ids_vm in ids_vms:
        vals = []
        for param, value in zip(['model', 'step'], values):
            val = set_vnf_param(ids_vm['mgmt'], param, value)
            vals.append(val)
        print(ids_vm['vm'], vals)
