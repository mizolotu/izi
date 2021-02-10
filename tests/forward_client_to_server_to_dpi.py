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
    parser.add_argument('-l', '--label', help='DSCP label', default=1, type=int)
    parser.add_argument('-i', '--ids', help='IDS number', default=1, type=int)
    parser.add_argument('-v', '--vms', help='File with vms', default='logs/vms.json')
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

    controllers = ['odl']
    controller_vm = [vm for vm in vms if vm['vm'] in controllers]
    assert len(controller_vm) == 1
    controller_name = controller_vm[0]['vm']
    controller_ip = controller_vm[0]['ip']

    if controller_name == 'odl':
        controller = Odl(controller_ip)

    default_table = 0
    arp_table = 1
    ip_ids_table = 4
    ip_dpi_table = 5

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
    ip_s_gw = gateway(ip_s)
    ip_d_gw = gateway(ip_d)
    ip_s_nat = nat_ip(ip_s, prefix='2{0}'.format(str(args.ids)))
    ip_s_nat_gw = gateway(ip_s_nat)
    ip_d_nat = nat_ip(ip_d, prefix='2{0}'.format(str(args.ids)))
    ip_d_nat_gw = gateway(ip_d_nat)
    mac_s = mac_hex(ip_s)[0]
    mac_d = mac_hex(ip_d)[0]
    mac_s_gw = mac_hex(ip_s_gw)[0]
    mac_d_gw = mac_hex(ip_d_gw)[0]
    sport = [args.application, 'source']
    dport = [args.application, 'destination']
    proto = ip_ptoto(args.protocol)

    dscp = args.label

    dscp_new = dscp + 2 ** (args.ids - 1)
    ids = 'dpi{0}'.format(args.ids)
    ids_br_mac = ':'.join([hex(int(nodes[ids].split(':')[1]))[i:i + 2] for i in range(2, 16, 2)][:-1])

    # ovs arp

    if container_s['vm'] in nodes.keys():
        tunnel_to_ids = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == container_s['vm'] and tunnel['remote'] == ids]
        assert len(tunnel_to_ids) == 1
        tunnel_to_ids = tunnel_to_ids[0]
        controller.arp_spa_tpa_mod_tpa_and_output(nodes[container_s['vm']], arp_table, high_priority, ip_s_nat_gw, ip_s_nat, ip_hex(ip_s), container_s['ofport'])
        controller.arp_spa_tpa_mod_spa_and_output(nodes[container_s['vm']], arp_table, high_priority, ip_s, ip_s_nat_gw, ip_hex(ip_s_nat), tunnel_to_ids)
    else:
        tunnel_to_ids = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == ids]
        assert len(tunnel_to_ids) == 1
        tunnel_to_ids = tunnel_to_ids[0]
        vxlan = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == container_s['vm']]
        assert len(vxlan) == 1
        vxlan = vxlan[0]
        controller.arp_spa_tpa_mod_tpa_and_output(nodes['gw'], arp_table, high_priority, ip_s_nat_gw, ip_s_nat, ip_hex(ip_s), vxlan)
        controller.arp_spa_tpa_mod_spa_and_output(nodes['gw'], arp_table, high_priority, ip_s, ip_s_nat_gw, ip_hex(ip_s_nat), tunnel_to_ids)

    if container_d['vm'] in nodes.keys():
        tunnel_to_ids = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == container_d['vm'] and tunnel['remote'] == ids]
        assert len(tunnel_to_ids) == 1
        tunnel_to_ids = tunnel_to_ids[0]
        controller.arp_spa_tpa_mod_tpa_and_output(nodes[container_d['vm']], arp_table, high_priority, ip_d_nat_gw, ip_d_nat, ip_hex(ip_d), container_d['ofport'])
        controller.arp_spa_tpa_mod_spa_and_output(nodes[container_d['vm']], arp_table, high_priority, ip_d, ip_d_nat_gw, ip_hex(ip_d_nat), tunnel_to_ids)
    else:
        tunnel_to_ids = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == ids]
        assert len(tunnel_to_ids) == 1
        tunnel_to_ids = tunnel_to_ids[0]
        vxlan = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == container_d['vm']]
        assert len(vxlan) == 1
        vxlan = vxlan[0]
        controller.arp_spa_tpa_mod_tpa_and_output(nodes['gw'], arp_table, high_priority, ip_d_nat_gw, ip_d_nat, ip_hex(ip_d), vxlan)
        controller.arp_spa_tpa_mod_spa_and_output(nodes['gw'], arp_table, high_priority, ip_d, ip_d_nat_gw, ip_hex(ip_d_nat), tunnel_to_ids)

    # ids arp

    if container_s['vm'] in nodes.keys():
        tunnel_to_src = [tunnel['ofport'] for tunnel in tunnels if tunnel['remote'] == container_s['vm'] and tunnel['vm'] == ids]
        assert len(tunnel_to_src) == 1
        tunnel_to_src = tunnel_to_src[0]
    else:
        tunnel_to_src = [tunnel['ofport'] for tunnel in tunnels if tunnel['remote'] == 'gw' and tunnel['vm'] == ids]
        assert len(tunnel_to_src) == 1
        tunnel_to_src = tunnel_to_src[0]
    controller.arp_output(nodes[ids], arp_table, high_priority, ip_s_nat, tunnel_to_src)

    if container_d['vm'] in nodes.keys():
        tunnel_to_dst = [tunnel['ofport'] for tunnel in tunnels if tunnel['remote'] == container_d['vm'] and tunnel['vm'] == ids]
        assert len(tunnel_to_dst) == 1
        tunnel_to_dst = tunnel_to_dst[0]
    else:
        tunnel_to_dst = [tunnel['ofport'] for tunnel in tunnels if tunnel['remote'] == 'gw' and tunnel['vm'] == ids]
        assert len(tunnel_to_dst) == 1
        tunnel_to_dst = tunnel_to_dst[0]
    controller.arp_output(nodes[ids], arp_table, high_priority, ip_d_nat, tunnel_to_dst)

    controller.arp_output(nodes[ids], arp_table, high_priority, ip_s_nat_gw, 'LOCAL')
    if ip_d_nat_gw != ip_s_nat_gw:
        controller.arp_output(nodes[ids], arp_table, high_priority, ip_d_nat_gw, 'LOCAL')

    # ids ip

    controller.ip_src_dst_port_mod_mac_and_output(nodes[ids], ip_ids_table, high_priority, ip_s_nat, ip_d_nat, proto, dport, ids_br_mac, 'LOCAL')
    controller.ip_src_dst_port_mod_mac_and_output(nodes[ids], ip_ids_table, high_priority, ip_d_nat, ip_s_nat, proto, sport, ids_br_mac, 'LOCAL')
    controller.ip_src_dst_port_mac_output(nodes[ids], ip_ids_table, higher_priority, ip_s_nat, ip_d_nat, proto, dport, ids_br_mac, tunnel_to_src)
    controller.ip_src_dst_port_mac_output(nodes[ids], ip_ids_table, higher_priority, ip_d_nat, ip_s_nat, proto, sport, ids_br_mac, tunnel_to_dst)

    # ovs ip

    if container_s['vm'] in nodes.keys() and container_d['vm'] in nodes.keys():

        # request

        tunnel_to_ids = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == container_s['vm'] and tunnel['remote'] == ids]
        assert len(tunnel_to_ids) == 1
        tunnel_to_ids = tunnel_to_ids[0]
        tunnel_to_mon = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == container_s['vm'] and tunnel['remote'] == 'mon']
        assert len(tunnel_to_mon) == 1
        tunnel_to_mon = tunnel_to_mon[0]
        controller.ip_src_dst_port_dscp_mod_src_dst_output(nodes[container_s['vm']], ip_ids_table, high_priority, ip_s, ip_d, proto, dport, dscp, ip_s_nat, ip_d_nat, tunnel_to_ids)
        controller.ip_src_dst_port_mod_src_dst_mac_and_resubmit(nodes[container_s['vm']], ip_ids_table, high_priority, ip_s_nat, ip_d_nat, proto, dport, ip_s, ip_d, mac_s, ip_dpi_table)

        # reply

        tunnel_to_ids = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == container_d['vm'] and tunnel['remote'] == ids]
        assert len(tunnel_to_ids) == 1
        tunnel_to_ids = tunnel_to_ids[0]
        tunnel_to_mon = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == container_d['vm'] and tunnel['remote'] == 'mon']
        assert len(tunnel_to_mon) == 1
        tunnel_to_mon = tunnel_to_mon[0]
        controller.ip_src_dst_port_dscp_mod_src_dst_output(nodes[container_d['vm']], ip_ids_table, high_priority, ip_d, ip_s, proto, sport, dscp, ip_d_nat, ip_s_nat, tunnel_to_ids)
        controller.ip_src_dst_port_mod_src_dst_mac_and_resubmit(nodes[container_d['vm']], ip_ids_table, high_priority, ip_d_nat, ip_s_nat, proto, sport, ip_d, ip_s, mac_d, ip_dpi_table)

    elif container_s['vm'] in nodes.keys() and container_d['vm'] not in nodes.keys():

        # request

        tunnel_to_ids = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == container_s['vm'] and tunnel['remote'] == ids]
        assert len(tunnel_to_ids) == 1
        tunnel_to_ids = tunnel_to_ids[0]
        tunnel_to_mon = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == container_s['vm'] and tunnel['remote'] == 'mon']
        assert len(tunnel_to_mon) == 1
        tunnel_to_mon = tunnel_to_mon[0]
        controller.ip_src_dst_port_dscp_mod_src_dst_output(nodes[container_s['vm']], ip_ids_table, high_priority, ip_s, ip_d, proto, dport, dscp, ip_s_nat, ip_d_nat, tunnel_to_ids)
        controller.ip_src_dst_port_mod_src_dst_macs_and_resubmit(nodes[container_s['vm']], ip_ids_table, high_priority, ip_s_nat, ip_d_nat, proto, dport, ip_s, ip_d, mac_s, mac_s_gw, ip_dpi_table)

        tunnel_to_ids = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == ids]
        assert len(tunnel_to_ids) == 1
        tunnel_to_ids = tunnel_to_ids[0]
        tunnel_to_mon = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == 'mon']
        assert len(tunnel_to_mon) == 1
        tunnel_to_mon = tunnel_to_mon[0]
        controller.ip_src_dst_port_dscp_mod_src_dst_output(nodes['gw'], ip_ids_table, high_priority, ip_d, ip_s, proto, sport, dscp, ip_d_nat, ip_s_nat, tunnel_to_ids)
        controller.ip_src_dst_port_mod_src_dst_macs_and_resubmit(nodes['gw'], ip_ids_table, high_priority, ip_d_nat, ip_s_nat, proto, sport, ip_d, ip_s, mac_d, mac_d_gw, ip_dpi_table)

    elif container_s['vm'] not in nodes.keys() and container_d['vm'] in nodes.keys():

        # request

        tunnel_to_ids = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == ids]
        assert len(tunnel_to_ids) == 1
        tunnel_to_ids = tunnel_to_ids[0]
        tunnel_to_mon = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == 'mon']
        assert len(tunnel_to_mon) == 1
        tunnel_to_mon = tunnel_to_mon[0]
        controller.ip_src_dst_port_dscp_mod_src_dst_output(nodes['gw'], ip_ids_table, high_priority, ip_s, ip_d, proto, dport, dscp, ip_s_nat, ip_d_nat, tunnel_to_ids)
        controller.ip_src_dst_port_mod_src_dst_macs_and_resubmit(nodes['gw'], ip_ids_table, high_priority, ip_s_nat, ip_d_nat, proto, dport, ip_s, ip_d, mac_s, mac_s_gw, ip_dpi_table)

        # reply

        tunnel_to_ids = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == container_d['vm'] and tunnel['remote'] == ids]
        assert len(tunnel_to_ids) == 1
        tunnel_to_ids = tunnel_to_ids[0]
        tunnel_to_mon = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == container_d['vm'] and tunnel['remote'] == 'mon']
        assert len(tunnel_to_mon) == 1
        tunnel_to_mon = tunnel_to_mon[0]
        controller.ip_src_dst_port_dscp_mod_src_dst_output(nodes[container_d['vm']], ip_ids_table, high_priority, ip_d, ip_s, proto, sport, dscp, ip_d_nat, ip_s_nat, tunnel_to_ids)
        controller.ip_src_dst_port_mod_src_dst_macs_and_resubmit(nodes[container_d['vm']], ip_ids_table, high_priority, ip_d_nat, ip_s_nat, proto, sport, ip_d, ip_s, mac_d, mac_d_gw, ip_dpi_table)
