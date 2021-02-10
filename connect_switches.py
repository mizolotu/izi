import json
import argparse as arp

from common.ovs import *

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Connect switches with tunnels')
    parser.add_argument('-c', '--controller', help='Controller', default='odl')
    parser.add_argument('-i', '--iprefix', help='Internal OVS prefix', default='ovs')
    parser.add_argument('-e', '--eprefix', help='External OVS prefix', default='ext')
    parser.add_argument('-f', '--fprefix', help='Flow IDS prefix', default='ids')
    parser.add_argument('-d', '--dprefix', help='DPI prefix', default='dpi')
    parser.add_argument('-v', '--vms', help='File with vms', default='logs/vms.json')
    parser.add_argument('-n', '--nodes', help='File with node ids', default='logs/nodes.json')
    parser.add_argument('-t', '--tunnels', help='File with tunnels', default='logs/tunnels.json')
    args = parser.parse_args()

    with open(args.vms, 'r') as f:
        vms = json.load(f)

    int_vms = [vm for vm in vms if vm['vm'].startswith(args.iprefix)]
    gw_vms = [vm for vm in vms if vm['vm'] == 'gw']
    ids_vms = [vm for vm in vms if vm['vm'].startswith(args.fprefix)]
    dpi_vms = [vm for vm in vms if vm['vm'].startswith(args.dprefix)]
    mon_vms = [vm for vm in vms if vm['vm'] == 'mon']
    ext_vms = [vm for vm in vms if vm['vm'].startswith(args.eprefix)]

    assert len(gw_vms) == 1
    gw_vm = gw_vms[0]
    gw_ip = gw_vm['ip']

    assert len(mon_vms) == 1
    mon_vm = mon_vms[0]
    mon_ip = mon_vm['ip']

    # obtain node ids

    nodes = {}
    for n_vm in int_vms + gw_vms + ids_vms + dpi_vms:
        node_id = get_node_id(n_vm)
        nodes[n_vm['vm']] = node_id

    with open(args.nodes, 'w') as f:
        json.dump(nodes, f)

    # delete default flows from all the switches

    for vm in int_vms + gw_vms + mon_vms + ids_vms + dpi_vms:
        delete_flows(vm)

    # clean bridge ports

    for vm in int_vms + ext_vms + gw_vms + mon_vms + ids_vms + dpi_vms:
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

    # connect internal switches to gateway switch

    for vm in int_vms:
        vxlan = 'i{0}_gw'.format(vm['vm'].split(args.iprefix)[1])
        ofport = create_vxlan_tunnel(vm, vxlan, gw_ip)
        tunnels.append({'vm': vm['vm'], 'remote': 'gw', 'ofport': ofport})
        vxlan = 'gw_i{0}'.format(vm['vm'].split(args.iprefix)[1])
        ofport = create_vxlan_tunnel(gw_vm, vxlan, vm['ip'])
        tunnels.append({'vm': 'gw', 'remote': vm['vm'], 'ofport': ofport})

    # connect external switches to gateway switch

    for vm in ext_vms:
        vxlan = 'e{0}_gw'.format(vm['vm'].split(args.eprefix)[1])
        ofport = create_vxlan_tunnel(vm, vxlan, gw_ip)
        tunnels.append({'vm': vm['vm'], 'remote': 'gw', 'ofport': ofport})
        vxlan = 'gw_e{0}'.format(vm['vm'].split(args.eprefix)[1])
        ofport = create_vxlan_tunnel(gw_vm, vxlan, vm['ip'])
        tunnels.append({'vm': 'gw', 'remote': vm['vm'], 'ofport': ofport})

    # connect internal switches to monitor bridge

    for vm in int_vms:
        vxlan = 'i{0}_mon'.format(vm['vm'].split(args.iprefix)[1])
        ofport = create_vxlan_tunnel(vm, vxlan, mon_ip)
        tunnels.append({'vm': vm['vm'], 'remote': 'mon', 'ofport': ofport})
        vxlan = 'mon_i{0}'.format(vm['vm'].split(args.iprefix)[1])
        ofport = create_vxlan_tunnel(mon_vm, vxlan, vm['ip'])
        tunnels.append({'vm': 'mon', 'remote': vm['vm'], 'ofport': ofport})

    # connect gateway switch to monitor bridge

    ofport = create_vxlan_tunnel(gw_vm, 'gw_mon', mon_ip)
    tunnels.append({'vm': 'gw', 'remote': 'mon', 'ofport': ofport})
    ofport = create_vxlan_tunnel(mon_vm, 'mon_gw', gw_ip)
    tunnels.append({'vm': 'mon', 'remote': 'gw', 'ofport': ofport})

    # connect internal switches to ids ones

    for vm1 in int_vms:
        for vm2 in ids_vms:
            vxlan = 'i{0}_f{1}'.format(vm1['vm'].split(args.iprefix)[1], vm2['vm'].split(args.fprefix)[1])
            ofport = create_vxlan_tunnel(vm1, vxlan, vm2['ip'])
            tunnels.append({'vm': vm1['vm'], 'remote': vm2['vm'], 'ofport': ofport})
            vxlan = 'f{0}_i{1}'.format(vm2['vm'].split(args.fprefix)[1], vm1['vm'].split(args.iprefix)[1])
            ofport = create_vxlan_tunnel(vm2, vxlan, vm1['ip'])
            tunnels.append({'vm': vm2['vm'], 'remote': vm1['vm'], 'ofport': ofport})
        for vm2 in dpi_vms:
            vxlan = 'i{0}_d{1}'.format(vm1['vm'].split(args.iprefix)[1], vm2['vm'].split(args.dprefix)[1])
            ofport = create_vxlan_tunnel(vm1, vxlan, vm2['ip'])
            tunnels.append({'vm': vm1['vm'], 'remote': vm2['vm'], 'ofport': ofport})
            vxlan = 'd{0}_i{1}'.format(vm2['vm'].split(args.dprefix)[1], vm1['vm'].split(args.iprefix)[1])
            ofport = create_vxlan_tunnel(vm2, vxlan, vm1['ip'])
            tunnels.append({'vm': vm2['vm'], 'remote': vm1['vm'], 'ofport': ofport})

    # connect gateway switch to ids switches

    for vm in ids_vms:
        vxlan = 'gw_f{0}'.format(vm['vm'].split(args.fprefix)[1])
        ofport = create_vxlan_tunnel(gw_vm, vxlan, vm['ip'])
        tunnels.append({'vm': 'gw', 'remote': vm['vm'], 'ofport': ofport})
        vxlan = 'f{0}_gw'.format(vm['vm'].split(args.fprefix)[1])
        ofport = create_vxlan_tunnel(vm, vxlan, gw_ip)
        tunnels.append({'vm': vm['vm'], 'remote': 'gw', 'ofport': ofport})
    for vm in dpi_vms:
        vxlan = 'gw_d{0}'.format(vm['vm'].split(args.dprefix)[1])
        ofport = create_vxlan_tunnel(gw_vm, vxlan, vm['ip'])
        tunnels.append({'vm': 'gw', 'remote': vm['vm'], 'ofport': ofport})
        vxlan = 'd{0}_gw'.format(vm['vm'].split(args.dprefix)[1])
        ofport = create_vxlan_tunnel(vm, vxlan, gw_ip)
        tunnels.append({'vm': vm['vm'], 'remote': 'gw', 'ofport': ofport})

    with open(args.tunnels, 'w') as f:
        json.dump(tunnels, f)

    for vm in vms:
        if vm in ids_vms:
            vm['role'] = 'ids'
        elif vm in dpi_vms:
            vm['role'] = 'dpi'
        elif vm in int_vms:
            vm['role'] = 'ovs'
        elif vm in gw_vms:
            vm['role'] = 'gw'
        elif vm in ext_vms:
            vm['role'] = 'ext'
        elif vm in mon_vms:
            vm['role'] = 'mon'
        elif vm['vm'] == args.controller:
            vm['role'] = 'sdn'

    with open(args.vms, 'w') as f:
        json.dump(vms, f)

