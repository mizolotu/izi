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
    ips_vms = [vm for vm in vms if vm['role'] == 'ips']
    odl_vms = [vm for vm in vms if vm['role'] == 'sdn']
    assert len(odl_vms) == 1
    odl_vm = odl_vms[0]
    node_vms = ovs_vms + ids_vms + ips_vms

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
        delete_veth_pair(ovs_vm, bridge_name, traffic_generation_veth_prefix)
        delete_veth_pair(ovs_vm, bridge_name, obs_bridge_veth_prefix)
        delete_veth_pair(ovs_vm, bridge_name, reward_bridge_veth_prefix)

    # delete ips veth pairs

    for ips_vm in ips_vms:
        delete_veth_pair(ips_vm, bridge_name, ips_rcv_veth_prefix)
        delete_veth_pair(ips_vm, bridge_name, ips_normal_veth_prefix)
        delete_veth_pair(ips_vm, bridge_name, ips_attack_veth_prefix)

    # connect switches to ids and ips

    tunnels = []
    for vm1 in ovs_vms:
        ovs_name = vm1['vm']
        spl = ovs_name.split('_')
        env_idx = spl[1]
        for vm2 in ids_vms + ips_vms:
            _name = vm2['vm']
            spl = _name.split('_')
            if spl[1] == env_idx:
                vxlan = 's{0}_{1}'.format(vm1['vm'].split('ovs')[1], _name)
                ofport = create_vxlan_tunnel(vm1, vxlan, vm2['ip'])
                tunnels.append({'vm': vm1['vm'], 'remote': vm2['vm'], 'ofport': ofport, 'type': 'vxlan'})
                vxlan = '{0}_s{1}'.format(_name, vm1['vm'].split('ovs')[1])
                ofport = create_vxlan_tunnel(vm2, vxlan, vm1['ip'])
                tunnels.append({'vm': vm2['vm'], 'remote': vm1['vm'], 'ofport': ofport, 'type': 'vxlan'})

    # create veth pairs on ovs

    veths = []
    for ovs_vm in ovs_vms:
        ofport = create_veth_pair(ovs_vm, bridge_name, traffic_generation_veth_prefix)
        veths.append({'vm': ovs_vm['vm'], 'tag': traffic_generation_veth_prefix, 'ofport': ofport, 'type': 'veth'})
        ofport = create_veth_pair(ovs_vm, bridge_name, obs_bridge_veth_prefix)
        veths.append({'vm': ovs_vm['vm'], 'tag': obs_bridge_veth_prefix, 'ofport': ofport, 'type': 'veth'})
        ofport = create_veth_pair(ovs_vm, bridge_name, reward_bridge_veth_prefix)
        veths.append({'vm': ovs_vm['vm'], 'tag': reward_bridge_veth_prefix, 'ofport': ofport, 'type': 'veth'})

    # create veth pairs on ips

    for ips_vm in ips_vms:
        ofport = create_veth_pair(ips_vm, bridge_name, ips_rcv_veth_prefix)
        veths.append({'vm': ips_vm['vm'], 'tag': ips_rcv_veth_prefix, 'ofport': ofport, 'type': 'veth'})
        ofport = create_veth_pair(ips_vm, bridge_name, ips_normal_veth_prefix)
        veths.append({'vm': ips_vm['vm'], 'tag': ips_normal_veth_prefix, 'ofport': ofport, 'type': 'veth'})
        ofport = create_veth_pair(ips_vm, bridge_name, ips_attack_veth_prefix)
        veths.append({'vm': ips_vm['vm'], 'tag': ips_attack_veth_prefix, 'ofport': ofport, 'type': 'veth'})

    # save nodes

    with open(nodes_fpath, 'w') as f:
        json.dump(nodes, f)

    # save tunnels

    with open(ofports_fpath, 'w') as f:
        json.dump(tunnels + veths, f)