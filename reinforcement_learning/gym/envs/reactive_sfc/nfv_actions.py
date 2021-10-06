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

def set_vnf_param(ids_ip, ids_port, param, value, sleep_interval=0.1):
    uri = f'http://{ids_ip}:{ids_port}/{param}'
    ready = False
    while not ready:
        try:
            r = requests.post(uri, json={param: value})
            ready = True
        except:
            sleep(sleep_interval)
    value = r.json()[param]
    return value

if __name__ == '__main__':

    # load data

    with open(vms_fpath, 'r') as f:
        vms = json.load(f)

    with open(nodes_fpath, 'r') as f:
        nodes = json.load(f)

    # ids vms

    ids_vms = [vm for vm in vms if vm['role'] == 'ids']
    ids_nodes = [nodes[vm['vm']] for vm in ids_vms]

    # set param values

    model = 2
    dscp = 0

    for ids_vm in ids_vms:
        vals = []
        m_val = set_vnf_param(ids_vm['mgmt'], flask_port, 'model', model)
        d_val = set_vnf_param(ids_vm['mgmt'], flask_port, 'dscp', dscp)
        print(ids_vm['vm'], m_val, d_val)
        model += 1
        dscp += 1