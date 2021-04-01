import json

from common.ovs import *
from config import *

if __name__ == '__main__':

    # load vms

    with open(vms_fpath, 'r') as f:
        vms = json.load(f)

    # retrieve ovs, ids, tgu and fcu

    ovs_vms = [vm for vm in vms if vm['role'] == 'ovs']
    ids_vms = [vm for vm in vms if vm['role'] == 'ids']
    tgu_vms = [vm for vm in vms if vm['role'] == 'tgu']
    assert len(tgu_vms) == 1
    tgu_vm = tgu_vms[0]
    fcu_vms = [vm for vm in vms if vm['role'] == 'fcu']
    assert len(fcu_vms) == 1
    fcu_vm = fcu_vms[0]

    # obtain node ids

    nodes = {}
    for n_vm in ovs_vms + ids_vms:
        node_id = get_node_id(n_vm)
        nodes[n_vm['vm']] = node_id

    # delete default flows from all the switches

    for vm in ovs_vms + ids_vms + tgu_vms:
        delete_flows(vm)

    # clean bridge ports

    for vm in ovs_vms + ids_vms:
        clean_tunnel_ports(vm)
    for vm in tgu_vms:
        clean_ovs_ports(vm)

    # delete tgu veth pairs

    for ovs_vm in ovs_vms:
        spl = ovs_vm['vm'].split('_')
        idx = int(spl[1])
        delete_veth_pair(tgu_vm, idx)

    # connect switches with vxlan tunnels

    tunnels = []

    # connect switches to ids ones

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
                vxlan = 'i{0}_s{1}'.format(vm2['vm'].split('ids')[1], vm1['vm'].split('ovs')[1])
                ofport = create_vxlan_tunnel(vm2, vxlan, vm1['ip'])
                tunnels.append({'vm': vm2['vm'], 'remote': vm1['vm'], 'ofport': ofport})

    # create veth pairs on tgu

    for ovs_vm in ovs_vms:
        spl = ovs_vm['vm'].split('_')
        idx = int(spl[1])
        create_veth_pair(tgu_vm, idx)

    # connect switches to tgu

    for vm in ovs_vms:
        ovs_name = vm['vm']
        spl = ovs_name.split('_')
        env_idx = spl[1]
        vxlan = 's{0}_t'.format(vm['vm'].split('ovs')[1])
        ofport = create_vxlan_tunnel(vm, vxlan, tgu_vm['data'])
        tunnels.append({'vm': vm['vm'], 'remote': tgu_vm['vm'], 'ofport': ofport})
        vxlan = 't_s{0}'.format(vm['vm'].split('ovs')[1])
        ofport = create_vxlan_tunnel(tgu_vm, vxlan, vm['data'])
        tunnels.append({'vm': tgu_vm['vm'], 'remote': vm['vm'], 'ofport': ofport})

    # add default tgu flow

    for ovs_vm in ovs_vms:
        ovs_name = ovs_vm['vm']
        spl = ovs_name.split('_')
        env_idx = spl[1]
        add_default_tgu_flow(tgu_vm, env_idx)

    # add sflow agent to each ovs

    for ovs_vm in ovs_vms:
        add_sflow_agent(ovs_vm, fcu_vm['ip'])

    # save nodes

    with open(nodes_fpath, 'w') as f:
        json.dump(nodes, f)

    # save tunnels

    with open(tunnels_fpath, 'w') as f:
        json.dump(tunnels, f)