import json

from common.odl import Odl
from config import *
from common.utils import ip_ptoto

def mirror_ip_to_ids(controller, ovs_node, table_id, priority, ips, tunnels, ovs, ids):
    tunnel_to_ids = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == ovs and tunnel['remote'] == ids]
    assert len(tunnel_to_ids) == 1
    tunnel_to_ids = tunnel_to_ids[0]
    for ip in ips:
        for ip_direction in directions:
            flow_id = '{0}_{1}_output_{2}'.format(ip_direction, ip, tunnel_to_ids)
            if controller.flow_exists_in_config(ovs_node, table_id, flow_id) or controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                controller.delete_config_flow(ovs_node, table_id, flow_id)
                controller.delete_operational_flow(ovs_node, table_id, flow_id)
            else:
                controller.ip_output_and_resubmit(ovs_node, table_id, priority, ip_direction, ip, tunnel_to_ids, table_id + 1)

def mirror_app_to_ids(controller, ovs_node, table_id, priority, application, tunnels, ovs, ids):
    tunnel_to_ids = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == ovs and tunnel['remote'] == ids]
    assert len(tunnel_to_ids) == 1
    tunnel_to_ids = tunnel_to_ids[0]
    proto_name = application[0]
    _, proto_number = ip_ptoto(proto_name)
    port = application[1]
    for port_dir in directions:
        flow_id = '{0}_{1}_{2}_output_{3}'.format(proto_name, port_dir, port, tunnel_to_ids)
        if controller.flow_exists_in_config(ovs_node, table_id, flow_id) or controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
            controller.delete_config_flow(ovs_node, table_id, flow_id)
            controller.delete_operational_flow(ovs_node, table_id, flow_id)
        else:
            controller.app_output_and_resubmit(ovs_node, table_id, priority, proto_name, proto_number, port_dir, port, tunnel_to_ids, table_id + 1)


def block_ip(controller, ovs_node, table_id, priority, ips):
    for ip in ips:
        for ip_direction in directions:
            flow_id = '{0}_{1}_drop'.format(ip_direction, ip)
            if controller.flow_exists_in_config(ovs_node, table_id, flow_id) or controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                controller.delete_config_flow(ovs_node, table_id, flow_id)
                controller.delete_operational_flow(ovs_node, table_id, flow_id)
            else:
                controller.ip_drop(ovs_node, table_id, priority, ip_direction, ip)

if __name__ == '__main__':

    # load data

    with open(vms_fpath, 'r') as f:
        vms = json.load(f)

    with open(nodes_fpath, 'r') as f:
        nodes = json.load(f)

    with open(tunnels_fpath, 'r') as f:
        tunnels = json.load(f)

    # ovs vm

    ovs_vms = sorted([vm for vm in vms if vm['role'] == 'ovs'])
    assert len(ovs_vms) == 1
    ovs_vm = ovs_vms[0]
    ovs_node = nodes[ovs_vm['vm']]

    # ids vms

    ids_vms = [vm for vm in vms if vm['role'] == 'ids']
    ids_nodes = [nodes[vm['vm']] for vm in ids_vms]
    assert (len(ids_nodes) + 5) <= ntables

    # controller

    controller_vm = [vm for vm in vms if vm['role'] == 'sdn']
    assert len(controller_vm) == 1
    controller_name = controller_vm[0]['vm']
    controller_ip = controller_vm[0]['ip']

    if controller_name == 'odl':
        controller = Odl(controller_ip)

    # action test

    ids_id = 1
    ids_name = 'ids{0}'.format(ids_id)
    loca_ips = ['172.31.69.25']
    remote_ips = ['18.221.219.4']
    app = ('tcp', 80)
    mirror_app_to_ids(controller, ovs_node, ids_tables[ids_id], priorities['high'], app, ids_name, tunnels)
    #mirror_ip_to_ids(controller, ovs_node, ids_tables[ids_id], priorities['high'], loca_ips, ids_name, tunnels)
    #block_ip(controller, ovs_node, block_table, priorities['high'], remote_ips)
