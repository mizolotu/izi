import json

from common.odl import Odl
from config import *
from common.ovs import delete_flows
from common.utils import ip_proto

def clean_ids_tables(controller, ids_nodes):

    # delete op flows and tables if there are any

    for node in ids_nodes:
        tables = controller.find_operational_tables(node)
        for table in tables:
            flows = controller.find_operational_flows(node, table)
            for flow in flows:
                controller.delete_operational_flow(node, table, flow)
            controller.delete_operational_table(node, table)

    # delete cfg flows and tables if there are any

    for node in ids_nodes:
        tables = controller.find_config_tables(node)
        for table in tables:
            flows = controller.find_config_flows(node, table)
            for flow in flows:
                controller.delete_config_flow(node, table, flow)
            controller.delete_config_table(node, table)

def init_ovs_tables(controller, ovs_vm, ovs_node, ovs_veths):

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

    delete_flows(ovs_vm)

    # default action flows

    in_ofports = [item['ofport'] for item in ovs_veths if item['tag'] == traffic_generation_veth_prefix]
    assert len(in_ofports) == 1
    in_ofport = in_ofports[0]
    obs_ofports = [item['ofport'] for item in ovs_veths if item['tag'] == obs_bridge_veth_prefix]
    assert len(obs_ofports) == 1
    obs_ofport = obs_ofports[0]
    reward_ofports = [item['ofport'] for item in ovs_veths if item['tag'] == reward_bridge_veth_prefix]
    assert len(reward_ofports) == 1
    reward_ofport = reward_ofports[0]
    controller.default_input_output_and_resubmit(ovs_node, in_table, priorities['lowest'], in_ofport, obs_ofport, in_table + 1)

    for app in applications:
        proto_name, proto_number = ip_proto(app[0])
        if len(app) == 2:
            port = app[1]
            for dir in ['source', 'destination']:
                controller.app_resubmit(ovs_node, in_table + 1, priorities['lower'], proto_name, proto_number, dir, port, in_table + 2)
        elif len(app) == 1:
            controller.proto_resubmit(ovs_node, in_table + 1, priorities['lowest'], proto_name, proto_number, in_table + 2)

    for ip in attackers:
        for dir in ['source', 'destination']:
            controller.ip_resubmit(ovs_node, in_table + 2, priorities['lower'], dir, ip, ids_tables[0])

    for i in range(in_table + 2, out_table):
        controller.default_resubmit(ovs_node, i, priorities['lowest'], i + 1)

    for ip in attackers:
        for dir in ['source', 'destination']:
            controller.ip_resubmit(ovs_node, out_table - 1, priorities['lower'], dir, ip, out_table)

    controller.default_output(ovs_node, out_table, priorities['lowest'], reward_ofport)

if __name__ == '__main__':

    # env index

    env_idx = 0

    # load data

    with open(vms_fpath, 'r') as f:
        vms = json.load(f)

    with open(nodes_fpath, 'r') as f:
        nodes = json.load(f)

    with open(ofports_fpath, 'r') as f:
        ofports = json.load(f)

    # ovs vm

    ovs_vms = [vm for vm in vms if vm['role'] == 'ovs' and int(vm['vm'].split('_')[1]) == env_idx]
    assert len(ovs_vms) == 1
    ovs_vm = ovs_vms[0]
    ovs_node = nodes[ovs_vm['vm']]

    # ids vms

    ids_vms = [vm for vm in vms if vm['role'] == 'ids' and int(vm['vm'].split('_')[1]) == env_idx]
    ids_nodes = [nodes[vm['vm']] for vm in ids_vms]
    assert (len(ids_nodes) + 2) <= out_table

    # controller

    controller_vm = [vm for vm in vms if vm['role'] == 'sdn']
    assert len(controller_vm) == 1
    controller_name = controller_vm[0]['vm']
    controller_ip = controller_vm[0]['ip']
    controller = Odl(controller_ip)

    # init tables

    ovs_veths = [item for item in ofports if item['type'] == 'veth' and item['vm'] == ovs_vm['vm']]
    init_ovs_tables(controller, ovs_vm, ovs_node, ovs_veths)

    # clean ids nodes

    clean_ids_tables(controller, ids_nodes)