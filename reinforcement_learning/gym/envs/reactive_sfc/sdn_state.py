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

def get_flag_counts(flow_collector_ip, flow_collector_port, flow_table):
    url = f'http://{flow_collector_ip}:{flow_collector_port}/flag_counts'
    samples = requests.get(url, json={'table': flow_table}).json()
    return samples

def get_app_counts(flow_collector_ip, flow_collector_port, flow_table):
    url = f'http://{flow_collector_ip}:{flow_collector_port}/app_counts'
    samples = requests.get(url, json={'table': flow_table}).json()
    return samples

def get_ip_counts(flow_collector_ip, flow_collector_port, flow_table):
    url = f'http://{flow_collector_ip}:{flow_collector_port}/ip_counts'
    samples = requests.get(url, json={'table': flow_table}).json()
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
        except Exception as e:
            print(e)
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
    for i in range(nsteps):
        tstep = time()
        samples0 = get_flag_counts(ovs_vm['mgmt'], flask_port, flag_table)
        samples1 = get_app_counts(ovs_vm['mgmt'], flask_port, app_table)
        samples2 = get_ip_counts(ovs_vm['mgmt'], flask_port, block_table)
        print(samples0, samples1, samples2)
        tdelta = time() - tstep
        if tdelta < episode_duration / nsteps:
            print(f'Sleeping for {episode_duration / nsteps - tdelta} seconds')
            sleep(episode_duration / nsteps - tdelta)
        print('Time elapsed: {0}'.format(time() - tstep))