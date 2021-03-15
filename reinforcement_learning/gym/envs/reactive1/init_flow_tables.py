import json

from common.odl import Odl
from common.utils import ip_proto
from config import *

def clean_ids_tables(controller, ids_nodes):

    # delete op flows if there are any

    for node in ids_nodes:
        tables = controller.find_operational_tables(node)
        for table in tables:
            flows = controller.find_operational_flows(node, table)
            for flow in flows:
                controller.delete_operational_flow(node, table, flow)

    # delete cfg flows if there are any

    for node in ids_nodes:
        tables = controller.find_config_tables(node)
        for table in tables:
            flows = controller.find_config_flows(node, table)
            for flow in flows:
                controller.delete_config_flow(node, table, flow)

def init_ovs_tables(controller, ovs_node):

    # delete flows if there are any

    tables = controller.find_operational_tables(ovs_node)
    for table in tables:
        flows = controller.find_operational_flows(ovs_node, table)
        for flow in flows:
            controller.delete_operational_flow(ovs_node, table, flow)

    tables = controller.find_config_tables(ovs_node)
    for table in tables:
        flows = controller.find_config_flows(ovs_node, table)
        for flow in flows:
            controller.delete_config_flow(ovs_node, table, flow)

    # default action flows

    for i in range(ntables):
        controller.default_resubmit(ovs_node, i, priorities['lowest'], i + 1)

    for application in applications:
        if len(application) == 2:
            proto_name = application[0]
            _, proto_number = ip_proto(proto_name)
            port = application[1]
            for port_direction in directions:
                controller.app_resubmit(ovs_node, app_table, priorities['medium'], proto_name, proto_number, port_direction, port, app_table + 1)
        elif len(application) == 1:
            proto_name = application[0]
            _, proto_number = ip_proto(proto_name)
            controller.proto_resubmit(ovs_node, app_table, priorities['lower'], proto_name, proto_number, app_table + 1)

    # reward flows

    for i in reward_tables:
        for ip_direction in directions:
            for ip in list(set(attackers)):
                controller.ip_resubmit(ovs_node, i, priorities['lower'], ip_direction, ip, i + 1)

if __name__ == '__main__':

    # env index

    env_idx = 0

    # load data

    with open(vms_fpath, 'r') as f:
        vms = json.load(f)

    with open(nodes_fpath, 'r') as f:
        nodes = json.load(f)

    with open(tunnels_fpath, 'r') as f:
        tunnels = json.load(f)

    # ovs vm

    ovs_vms = [vm for vm in vms if vm['role'] == 'ovs' and int(vm['vm'].split('_')[1]) == env_idx]
    assert len(ovs_vms) == 1
    ovs_vm = ovs_vms[0]
    ovs_node = nodes[ovs_vm['vm']]

    # ids vms

    ids_vms = [vm for vm in vms if vm['role'] == 'ids' and int(vm['vm'].split('_')[1]) == env_idx]
    ids_nodes = [nodes[vm['vm']] for vm in ids_vms]
    assert (len(ids_nodes) + 5) <= ntables

    # controller

    controller_vm = [vm for vm in vms if vm['role'] == 'sdn']
    assert len(controller_vm) == 1
    controller_name = controller_vm[0]['vm']
    controller_ip = controller_vm[0]['ip']

    if controller_name == 'odl':
        controller = Odl(controller_ip)

    # init tables

    init_ovs_tables(controller, ovs_node)

    # clean ids nodes

    clean_ids_tables(controller, ids_nodes)