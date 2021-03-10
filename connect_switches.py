import json

from common.ovs import *
from config import *

if __name__ == '__main__':

    with open(vms_fpath, 'r') as f:
        vms = json.load(f)

    ovs_vms = [vm for vm in vms if vm['vm'].startswith('ovs')]
    ids_vms = [vm for vm in vms if vm['vm'].startswith('ids')]

    # obtain node ids

    nodes = {}
    for n_vm in ovs_vms + ids_vms:
        node_id = get_node_id(n_vm)
        nodes[n_vm['vm']] = node_id

    with open(nodes_fpath, 'w') as f:
        json.dump(nodes, f)

    # delete default flows from all the switches

    for vm in ovs_vms + ids_vms:
        delete_flows(vm)

    # clean bridge ports

    for vm in ovs_vms + ids_vms:
        clean_tunnel_ports(vm)

    # connect switches with vxlan tunnels

    tunnels = []

    # connect internal switches to ids ones

    for vm1 in ovs_vms:
        ovs_name = vm1['vm']
        spl = ovs_name.split('_')
        env_idx = spl[1]
        for vm2 in ids_vms:
            ids_name = vm2['vm']
            spl = ids_name.split('_')
            if spl[1] == env_idx:
                vxlan = 's{0}_i{1}'.format(vm1['vm'].split('ovs')[1], vm2['vm'].split('ids')[1])
                ofport = create_vxlan_tunnel(vm1, vxlan, vm2['ip'])
                tunnels.append({'vm': vm1['vm'], 'remote': vm2['vm'], 'ofport': ofport})
                vxlan = 'f{0}_i{1}'.format(vm2['vm'].split('ids')[1], vm1['vm'].split('ovs')[1])
                ofport = create_vxlan_tunnel(vm2, vxlan, vm1['ip'])
                tunnels.append({'vm': vm2['vm'], 'remote': vm1['vm'], 'ofport': ofport})

    with open(tunnels_fpath, 'w') as f:
        json.dump(tunnels, f)

    for vm in vms:
        if vm in ids_vms:
            vm['role'] = 'ids'
        elif vm in ovs_vms:
            vm['role'] = 'ovs'
        elif vm['vm'] == ctrl_name:
            vm['role'] = 'sdn'

    with open(vms_fpath, 'w') as f:
        json.dump(vms, f)