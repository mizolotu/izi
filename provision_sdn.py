import vagrant, json
import argparse as arp

from common.utils import *
from common.ovs import *
from common.odl import Odl

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Create networks')
    parser.add_argument('-v', '--vms', help='File with vms', default='logs/vms.json')
    parser.add_argument('-i', '--iprefix', help='Internal OVS prefix', default='ovs')
    parser.add_argument('-t', '--tunnels', help='File with tunnels', default='logs/tunnels.json')
    parser.add_argument('-c', '--containers', help='File with containers', default='logs/containers.json')
    parser.add_argument('-n', '--nodes', help='File with nodes', default='logs/nodes.json')
    args = parser.parse_args()

    with open(args.vms, 'r') as f:
        vms = json.load(f)

    with open(args.nodes, 'r') as f:
        nodes = json.load(f)

    with open(args.tunnels, 'r') as f:
        tunnels = json.load(f)

    with open(args.containers, 'r') as f:
        containers = json.load(f)

    # ids vms

    ids_vms = [vm for vm in vms if vm['role'] == 'ids']
    dpi_vms = [vm for vm in vms if vm['role'] == 'dpi']

    # controller

    controller_vm = [vm for vm in vms if vm['role'] == 'sdn']
    assert len(controller_vm) == 1
    controller_name = controller_vm[0]['vm']
    controller_ip = controller_vm[0]['ip']

    if controller_name == 'odl':
        controller = Odl(controller_ip)

    # delete flows if there are any

    for node in nodes.values():
        tables = controller.find_tables(node)
        for table in tables:
            flows = controller.find_flows(node, table)
            for flow in flows:
                controller.delete_flow(node, table, flow)

    # table ids

    default_table = 0
    arp_table = 1
    ip_src_table = 2
    ip_ids_table = 3
    ip_dpi_table = 4
    ip_fw_table = 5
    ip_mon_table = 6
    ip_dst_table = 7

    # priorities

    low_priority = 0
    high_priority = 1

    # protocols

    arp_proto = 2054
    ip_proto = 2048

    # default flows

    for node in nodes.values():
        controller.resubmit_proto(node, default_table, low_priority, arp_proto, arp_table)
        controller.resubmit_proto(node, default_table, low_priority, ip_proto, ip_src_table)
        controller.resubmit_proto(node, ip_src_table, low_priority, ip_proto, ip_ids_table)
        controller.resubmit_proto(node, ip_ids_table, low_priority, ip_proto, ip_dpi_table)
        controller.resubmit_proto(node, ip_dpi_table, low_priority, ip_proto, ip_fw_table)
        controller.resubmit_proto(node, ip_fw_table, low_priority, ip_proto, ip_mon_table)

    # subnets and gateways

    subnets = []
    gateways = []
    for container in containers:
        gw_ip = gateway(container['ip'])
        if gw_ip not in gateways:
            gateways.append(gw_ip)
            subnets.append([container])
        else:
            idx = gateways.index(gw_ip)
            subnets[idx].append(container)

    # check that containers in the same subnet run on either only node vms or external switches

    ext_subnets = []
    for gw_ip, subnet in zip(gateways, subnets):
        vms = list(set([container['vm'] for container in subnet]))
        ext = True
        for node in nodes.keys():
            if node in vms:
                ext = False
                break
        if ext:
            ext_subnets.append(network(gw_ip))
            for vm in vms:
                assert vm not in nodes.keys()
        else:
            for vm in vms:
                assert vm in nodes.keys()
    ext_subnets = list(set(ext_subnets))

    # arp auto-responder

    for gw_ip in gateways:
        controller.arp_auto_reply(nodes['gw'], arp_table, low_priority, ip_hex(gw_ip), mac_hex(gw_ip))

    # add arp flows

    for subnet, gw_ip in zip(subnets, gateways):

        # arp destination flows

        for container in subnet:
            if container['vm'] in nodes.keys():
                controller.arp_output(nodes[container['vm']], arp_table, low_priority, container['ip'], container['ofport'])

        # tunnel to gw

        vms = set(list([container['vm'] for container in subnet if container['vm'] in nodes.keys()]))
        for vm in vms:
            vxlan = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == vm and tunnel['remote'] == 'gw']
            assert len(vxlan) == 1
            vxlan = vxlan[0]
            controller.arp_output(nodes[vm], arp_table, low_priority, gw_ip, vxlan)

        # tunnel to another ovs

        for container1 in subnet:
            for container2 in subnet:
                if container1['vm'] != container2['vm']:
                    vxlan = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == container1['vm'] and tunnel['remote'] == container2['vm']]
                    assert len(vxlan) == 1
                    vxlan = vxlan[0]
                    controller.arp_output(nodes[container1['vm']], 1, 0, container2['ip'], vxlan)

    # add ip src flows

    for container in containers:
        if container['vm'] in nodes.keys():
            vxlan = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == container['vm'] and tunnel['remote'] == 'mon']
            assert len(vxlan) == 1
            vxlan = vxlan[0]
            controller.ip_src_output_and_resubmit(nodes[container['vm']], ip_src_table, high_priority, container['ip'], vxlan, ip_ids_table)

    for ext_subnet in ext_subnets:
        vxlan = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == 'mon']
        assert len(vxlan) == 1
        vxlan = vxlan[0]
        controller.ip_src_output_and_resubmit(nodes['gw'], ip_src_table, high_priority, ext_subnet, vxlan, ip_ids_table, mask=24)

    # add ip mon flows in the same internal subnet

    for subnet, gw_ip in zip(subnets, gateways):

        # same ovs

        for container in subnet:
            if container['vm'] in nodes.keys():
                vxlan = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == container['vm'] and tunnel['remote'] == 'mon']
                assert len(vxlan) == 1
                vxlan = vxlan[0]
                controller.ip_dst_mod_ecn_and_output_and_resubmit(nodes[container['vm']], ip_mon_table, high_priority, container['ip'], 0, 2, vxlan, ip_dst_table)
                controller.ip_dst_mod_ecn_and_output_and_resubmit(nodes[container['vm']], ip_mon_table, high_priority, container['ip'], 1, 3, vxlan, ip_dst_table)

        # another ovs

        for container1 in subnet:
            for container2 in subnet:
                if container1['vm'] != container2['vm']:
                    vxlan = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == container1['vm'] and tunnel['remote'] == container2['vm']]
                    assert len(vxlan) == 1
                    vxlan = vxlan[0]
                    controller.ip_dst_output(nodes[container1['vm']], ip_mon_table, high_priority, container2['ip'], vxlan)

    # add ip mon flows to a different subnet

    for subnet1 in subnets:
        for subnet2, gw_ip in zip(subnets, gateways):
            if subnet1 != subnet2:
                for container in subnet1:
                    if container['vm'] in nodes.keys():
                        vxlan = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == container['vm'] and tunnel['remote'] == 'gw']
                        assert len(vxlan) == 1
                        vxlan = vxlan[0]
                        controller.ip_dst_output(nodes[container['vm']], ip_mon_table, high_priority, network(gw_ip), vxlan, mask=24)

    # add ip mon flows to an external subnet

    # to outside

    for ext_subnet in ext_subnets:
        vxlan = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == 'mon']
        assert len(vxlan) == 1
        vxlan = vxlan[0]
        controller.ip_dst_mod_ecn_and_output_and_resubmit(nodes['gw'], ip_mon_table, low_priority, ext_subnet, 0, 2, vxlan, ip_dst_table, mask=24)
        controller.ip_dst_mod_ecn_and_output_and_resubmit(nodes['gw'], ip_mon_table, low_priority, ext_subnet, 1, 3, vxlan, ip_dst_table, mask=24)

    # from outside

    for subnet in subnets:
        for container in subnet:
            if container['vm'] in nodes.keys():
                vxlan = [tunnel['ofport'] for tunnel in tunnels if tunnel['remote'] == container['vm'] and tunnel['vm'] == 'gw']
                assert len(vxlan) == 1
                vxlan = vxlan[0]
                for ext_subnet in ext_subnets:
                    gw_ip = gateway(ext_subnet)
                    controller.ip_dst_mod_mac_and_output(nodes['gw'], ip_mon_table, high_priority, container['ip'], mac_hex(gw_ip)[0], mac_hex(container['ip'])[0], vxlan)

    # add ip dst flows

    for subnet, gw_ip in zip(subnets, gateways):
        for container in subnet:
            if container['vm'] in nodes.keys():
                controller.ip_dst_mod_ecn_and_output(nodes[container['vm']], ip_dst_table, high_priority, container['ip'], 2, 0, container['ofport'])
                controller.ip_dst_mod_ecn_and_output(nodes[container['vm']], ip_dst_table, high_priority, container['ip'], 3, 1, container['ofport'])

    for subnet1, gw_ip in zip(subnets, gateways):
        for subnet2 in subnets:
            if subnet2 != subnet1:
                for container in subnet2:
                    if container['vm'] not in nodes.keys():
                        vxlan = [tunnel['ofport'] for tunnel in tunnels if tunnel['remote'] == container['vm'] and tunnel['vm'] == 'gw']
                        assert len(vxlan) == 1
                        vxlan = vxlan[0]
                        controller.ip_dst_mod_ecn_and_mac_and_output(nodes['gw'], ip_dst_table, high_priority, container['ip'], 2, mac_hex(gw_ip)[0], 0, mac_hex(container['ip'])[0], vxlan)
                        controller.ip_dst_mod_ecn_and_mac_and_output(nodes['gw'], ip_dst_table, high_priority, container['ip'], 3, mac_hex(gw_ip)[0], 1, mac_hex(container['ip'])[0], vxlan)

    # provision ids and dpi

    for gateway in gateways:
        for i,vm in enumerate(ids_vms):
            prefix = '1{0}'.format(i + 1)
            ip_gw = nat_ip(gateway, prefix)
            set_ip(vm, ip_gw)
        for i,vm in enumerate(dpi_vms):
            prefix = '2{0}'.format(i + 1)
            ip_gw = nat_ip(gateway, prefix)
            set_ip(vm, ip_gw)

