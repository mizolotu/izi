import json
import numpy as np

from common.odl import Odl
from config import *
from time import time

def get_flow_counts(controller, ovs_node, table, count_type='packet'):
    flow_ids, counts = controller.get_flow_statistics(ovs_node, table, count_type)
    counts = np.array([int(item) for item in counts])
    return flow_ids, counts

if __name__ == '__main__':

    # params

    env_idx = 0

    # load data

    with open(vms_fpath, 'r') as f:
        vms = json.load(f)

    with open(nodes_fpath, 'r') as f:
        nodes = json.load(f)

    with open(tunnels_fpath, 'r') as f:
        tunnels = json.load(f)

    # ovs vm

    ovs_vms = [vm for vm in vms if vm['role'] == 'ovs' and int(vm['vm'].split('_')[1]) == env_idx]
    assert len(ovs_vms) == 1
    ovs_vm = ovs_vms[0]
    ovs_node = nodes[ovs_vm['vm']]

    # ids vms

    ids_vms = [vm for vm in vms if vm['role'] == 'ids' and int(vm['vm'].split('_')[1]) == env_idx]
    ids_nodes = [nodes[vm['vm']] for vm in ids_vms]
    assert (len(ids_nodes) + 4) <= ntables

    # controller

    controller_vm = [vm for vm in vms if vm['role'] == 'sdn']
    assert len(controller_vm) == 1
    controller_name = controller_vm[0]['vm']
    controller_ip = controller_vm[0]['ip']

    if controller_name == 'odl':
        controller = Odl(controller_ip)

    tstart = time()
    print('Observation:')
    ids, counts = get_flow_counts(controller, ovs_node, app_table)
    for id, count in zip(ids, counts):
        print(id, count)
    print('Reward:')
    for reward_table in reward_tables:
        ids, counts = get_flow_counts(controller, ovs_node, reward_table)
        for id, count in zip(ids, counts):
            print(id, count)
    print('Time elapsed: {0}'.format(time() - tstart))