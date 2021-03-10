import json, requests

from config import *

def reset_ids(ids_ip):
    uri = 'http://{0}:5000/reset'.format(ids_ip)
    requests.get(uri)

def set_vnf_param(ids_ip, param, value):
    uri = 'http://{0}:5000/{1}'.format(ids_ip, param)
    r = requests.post(uri, json={param: value})
    value = float(r.json()[param])
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
