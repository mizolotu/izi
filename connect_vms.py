import json

from common.ovs import *
from config import *

if __name__ == '__main__':

    # load vms

    with open(vms_fpath, 'r') as f:
        vms = json.load(f)

    # retrieve ovs and ids vms

    ovs_vms = [vm for vm in vms if vm['role'] == 'ovs']
    ids_vms = [vm for vm in vms if vm['role'] == 'ids']
    odl_vms = [vm for vm in vms if vm['role'] == 'sdn']
    assert len(odl_vms) == 1
    odl_vm = odl_vms[0]
    node_vms = ovs_vms + ids_vms

    # connect ovs and ids vms to odl

    for vm in node_vms:
        connect_to_controller(vm, bridge_name, odl_vm['ip'], ctrl_port)

    # obtain node ids

    nodes = {}
    for n_vm in node_vms:
        node_id = get_node_id(n_vm)
        nodes[n_vm['vm']] = node_id

    # delete default flows from all the switches

    for vm in node_vms:
        delete_flows(vm)

    # clean bridge ports

    for vm in node_vms:
        clean_tunnel_ports(vm)

    # delete ovs veth pairs

    for ovs_vm in ovs_vms:
        delete_veth_pair(ovs_vm, bridge_name, in_veth_prefix)
        delete_veth_pair(ovs_vm, bridge_name, out_veth_prefix)

    # delete ids veth pairs

    for ids_vm in ids_vms:
        delete_veth_pair(ids_vm, bridge_name, in_veth_prefix)
        delete_veth_pair(ids_vm, bridge_name, out_veth_prefix)

    # connect switches to ids

    tunnels = []
    for vm1 in ovs_vms:
        ovs_name = vm1['vm']
        spl = ovs_name.split('_')
        env_idx = spl[1]
        for vm2 in ids_vms:
            _name = vm2['vm']
            spl = _name.split('_')
            if spl[1] == env_idx:
                vxlan = 's{0}_i{1}'.format(vm1['vm'].split('ovs')[1], vm2['vm'].split('ids')[1])
                ofport = create_vxlan_tunnel(vm1, vxlan, vm2['ip'])
                tunnels.append({'vm': vm1['vm'], 'remote': vm2['vm'], 'ofport': ofport, 'type': 'vxlan'})
                vxlan = 'i{0}_s{1}'.format(vm2['vm'].split('ids')[1], vm1['vm'].split('ovs')[1])
                ofport = create_vxlan_tunnel(vm2, vxlan, vm1['ip'])
                tunnels.append({'vm': vm2['vm'], 'remote': vm1['vm'], 'ofport': ofport, 'type': 'vxlan'})

    # create veth pairs on ovs

    veths = []
    for ovs_vm in ovs_vms:
        ofport = create_veth_pair(ovs_vm, bridge_name, in_veth_prefix)
        veths.append({'vm': ovs_vm['vm'], 'tag': in_veth_prefix, 'ofport': ofport, 'type': 'veth'})
        ofport = create_veth_pair(ovs_vm, bridge_name, out_veth_prefix)
        veths.append({'vm': ovs_vm['vm'], 'tag': out_veth_prefix, 'ofport': ofport, 'type': 'veth'})

    # create veth pairs on ids

    for ids_vm in ids_vms:
        ofport = create_veth_pair(ids_vm, bridge_name, in_veth_prefix)
        veths.append({'vm': ids_vm['vm'], 'tag': in_veth_prefix, 'ofport': ofport, 'type': 'veth'})
        ofport = create_veth_pair(ids_vm, bridge_name, out_veth_prefix)
        veths.append({'vm': ids_vm['vm'], 'tag': out_veth_prefix, 'ofport': ofport, 'type': 'veth'})

    # save nodes

    with open(nodes_fpath, 'w') as f:
        json.dump(nodes, f)

    # save tunnels

    with open(ofports_fpath, 'w') as f:
        json.dump(tunnels + veths, f)