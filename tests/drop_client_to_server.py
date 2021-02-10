import json
import argparse as arp

from common.odl import *
from common.utils import nat_ip, gateway, ip_hex, ip_ptoto, mac_hex

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Forward flow to IDS.')
    parser.add_argument('-s', '--source', help='Client name', default='client1')
    parser.add_argument('-d', '--destination', help='Server name', default='server3')
    parser.add_argument('-p', '--protocol', help='Protocol', default='tcp')
    parser.add_argument('-a', '--application', help='Application port', default=5000, type=int)
    parser.add_argument('-l', '--label', help='DSCP label', default=9, type=int)
    parser.add_argument('-v', '--vms', help='File with vms', default='logs/vms.json')
    parser.add_argument('-c', '--containers', help='File with containers', default='logs/containers.json')
    parser.add_argument('-n', '--nodes', help='File with nodes', default='logs/nodes.json')
    args = parser.parse_args()

    with open(args.vms, 'r') as f:
        vms = json.load(f)

    with open(args.nodes, 'r') as f:
        nodes = json.load(f)

    with open(args.containers, 'r') as f:
        containers = json.load(f)

    controllers = ['odl']
    controller_vm = [vm for vm in vms if vm['vm'] in controllers]
    assert len(controller_vm) == 1
    controller_name = controller_vm[0]['vm']
    controller_ip = controller_vm[0]['ip']

    if controller_name == 'odl':
        controller = Odl(controller_ip)

    ip_fw_table = 5

    high_priority = 1
    higher_priority = 2

    container_s = [container for container in containers if container['name'] == args.source]
    assert len(container_s) == 1
    container_s = container_s[0]
    container_d = [container for container in containers if container['name'] == args.destination]
    assert len(container_d) == 1
    container_d = container_d[0]

    ip_s = container_s['ip']
    ip_d = container_d['ip']
    sport = [args.application, 'source']
    dport = [args.application, 'destination']
    proto = ip_ptoto(args.protocol)

    dscp = args.label

    # ovs ip

    if container_s['vm'] in nodes.keys() and container_d['vm'] in nodes.keys():
        controller.ip_src_dst_port_dscp_drop(nodes[container_s['vm']], ip_fw_table, high_priority, ip_s, ip_d, proto, dport, dscp)
        controller.ip_src_dst_port_dscp_drop(nodes[container_d['vm']], ip_fw_table, high_priority, ip_d, ip_s, proto, sport, dscp)
    elif container_s['vm'] in nodes.keys() and container_d['vm'] not in nodes.keys():
        controller.ip_src_dst_port_dscp_drop(nodes[container_s['vm']], ip_fw_table, high_priority, ip_s, ip_d, proto, dport, dscp)
        controller.ip_src_dst_port_dscp_drop(nodes['gw'], ip_fw_table, high_priority, ip_d, ip_s, proto, sport, dscp)
    elif container_s['vm'] not in nodes.keys() and container_d['vm'] in nodes.keys():
        controller.ip_src_dst_port_dscp_drop(nodes['gw'], ip_fw_table, high_priority, ip_s, ip_d, proto, dport, dscp)
        controller.ip_src_dst_port_dscp_drop(nodes[container_d['vm']], ip_fw_table, high_priority, ip_d, ip_s, proto, sport, dscp)
