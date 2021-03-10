import json
import argparse as arp

from common.ovs import *

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Connect switches with tunnels')
    parser.add_argument('-c', '--controller', help='Controller', default='odl')
    parser.add_argument('-i', '--iprefix', help='Internal OVS prefix', default='ovs')
    parser.add_argument('-f', '--fprefix', help='Flow IDS prefix', default='ids')
    parser.add_argument('-v', '--vms', help='File with vms', default='logs/vms.json')
    parser.add_argument('-n', '--nodes', help='File with node ids', default='logs/nodes.json')
    parser.add_argument('-t', '--tunnels', help='File with tunnels', default='logs/tunnels.json')
    args = parser.parse_args()

    with open(args.vms, 'r') as f:
        vms = json.load(f)

    int_vms = [vm for vm in vms if vm['vm'].startswith(args.iprefix)]
    ids_vms = [vm for vm in vms if vm['vm'].startswith(args.fprefix)]

    # obtain node ids

    nodes = {}
    for n_vm in int_vms + ids_vms:
        node_id = get_node_id(n_vm)
        nodes[n_vm['vm']] = node_id

    with open(args.nodes, 'w') as f:
        json.dump(nodes, f)

    # delete default flows from all the switches

    for vm in int_vms + ids_vms:
        delete_flows(vm)

    # clean bridge ports

    for vm in int_vms + ids_vms:
        clean_tunnel_ports(vm)

    # connect switches with vxlan tunnels

    tunnels = []

    # connect internal switches to each other

    for vm1 in int_vms:
        for vm2 in int_vms:
            if vm1 != vm2:
                vxlan = 'i{0}_i{1}'.format(vm1['vm'].split(args.iprefix)[1], vm2['vm'].split(args.iprefix)[1])
                ofport = create_vxlan_tunnel(vm1 ,vxlan, vm2['ip'])
                tunnels.append({'vm': vm1['vm'], 'remote': vm2['vm'], 'ofport': ofport})

    # connect internal switches to ids ones

    for vm1 in int_vms:
        for vm2 in ids_vms:
            vxlan = 'i{0}_f{1}'.format(vm1['vm'].split(args.iprefix)[1], vm2['vm'].split(args.fprefix)[1])
            ofport = create_vxlan_tunnel(vm1, vxlan, vm2['ip'])
            tunnels.append({'vm': vm1['vm'], 'remote': vm2['vm'], 'ofport': ofport})
            vxlan = 'f{0}_i{1}'.format(vm2['vm'].split(args.fprefix)[1], vm1['vm'].split(args.iprefix)[1])
            ofport = create_vxlan_tunnel(vm2, vxlan, vm1['ip'])
            tunnels.append({'vm': vm2['vm'], 'remote': vm1['vm'], 'ofport': ofport})

    with open(args.tunnels, 'w') as f:
        json.dump(tunnels, f)

    for vm in vms:
        if vm in ids_vms:
            vm['role'] = 'ids'
        elif vm in int_vms:
            vm['role'] = 'ovs'
        elif vm['vm'] == args.controller:
            vm['role'] = 'sdn'

    with open(args.vms, 'w') as f:
        json.dump(vms, f)