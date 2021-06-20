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
    samples = requests.get(url, json={'window': flow_window}).json()
    return samples

def get_flow_report(flow_collector_ip, flow_collector_port):
    url = f'http://{flow_collector_ip}:{flow_collector_port}/report'
    jdata = requests.get(url).json()
    return jdata['in_pkts'][::-1], jdata['out_pkts'][::-1], jdata['timestamps'][::-1]

def reset_flow_collector(ovs_ip, ovs_port, sleep_interval=0.1):
    uri = f'http://{ovs_ip}:{ovs_port}/reset'
    ready = False
    while not ready:
        try:
            requests.get(uri)
            ready = True
        except:
            sleep(sleep_interval)

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

    reset_flow_collector(ovs_vm['mgmt'], flask_port)
    tstart = time()
    nsamples = 0
    print('Observation:')
    for i in range(80):
        samples = get_flow_samples(ovs_vm['mgmt'], flask_port, flow_window)
        nsamples += len(samples)
        print('Time elapsed: {0}'.format(time() - tstart))
        sleep(0.25)
    in_pkts, out_pkts, timestamps = get_flow_report(ovs_vm['mgmt'], flask_port)
    print(len(in_pkts), len(out_pkts), len(timestamps), nsamples)