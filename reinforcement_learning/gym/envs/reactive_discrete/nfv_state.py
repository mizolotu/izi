import json, requests

from config import *

def get_vnf_param(ids_ip, ids_port, param):
    uri = f'http://{ids_ip}:{ids_port}/{param}'
    r = requests.get(uri)
    value = float(r.json()[param])
    return value

def get_intrusions(ids_ip, ids_port):
    uri = f'http://{ids_ip}:{ids_port}/intrusions'
    r = requests.get(uri)
    value = r.json()
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

    # get param values

    for ids_vm in ids_vms:
        vals = []
        for param in ['model', 'step', 'delay', 'nflows']:
            val = get_vnf_param(ids_vm['mgmt'], param)
            vals.append(val)
        intrusions = get_intrusions(ids_vm['mgmt'])
        print(ids_vm['vm'], vals, intrusions)
