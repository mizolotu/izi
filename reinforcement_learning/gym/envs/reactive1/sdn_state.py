import json, requests
import numpy as np

from config import *
from time import time, sleep

def get_flow_counts(controller, ovs_node, table, count_type='packet'):
    flow_ids, counts = controller.get_flow_statistics(ovs_node, table, count_type)
    counts = np.array([int(item) for item in counts])
    return flow_ids, counts

def get_flow_samples(flow_collector_ip, flow_collector_port, flow_window):
    url = f'http://{flow_collector_ip}:{flow_collector_port}/samples'
    in_samples, out_samples = requests.get(url, json={'window': flow_window}).json()
    return in_samples, out_samples

if __name__ == '__main__':

    # params

    env_idx = 0

    # load data

    with open(vms_fpath, 'r') as f:
        vms = json.load(f)

    with open(nodes_fpath, 'r') as f:
        nodes = json.load(f)

    # ovs vm

    ovs_vms = [vm for vm in vms if vm['role'] == 'ovs' and int(vm['vm'].split('_')[1]) == env_idx]
    assert len(ovs_vms) == 1
    ovs_vm = ovs_vms[0]
    ovs_node = nodes[ovs_vm['vm']]

    tstart = time()
    print('Observation:')
    while True:
        in_samples, out_samples = get_flow_samples(ovs_vm['mgmt'], flask_port, flow_window)
        if len(in_samples) > 0:
            print(in_samples[0])
        print('Time elapsed: {0}'.format(time() - tstart))
        sleep(1)