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

def set_vnf_model(ids_ip, ids_port, value):
    uri = f'http://{ids_ip}:{ids_port}/model'
    r = requests.post(uri, json={'model': value})
    value = r.json()['model']
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

    model = 1

    for ids_vm in ids_vms:
        vals = []
        val = set_vnf_model(ids_vm['mgmt'], flask_port, model)
        vals.append(val)
        print(ids_vm['vm'], vals)
        model += 1