import json

from common.odl import Odl
from config import *
from common.utils import ip_proto
from time import sleep

def mirror_app_to_ids(controller, ovs_node, table_id, lower_priority, higher_priority, application, ovs, ids, tunnels):
    tunnel_to_ids = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == ovs and tunnel['remote'] == ids]
    assert len(tunnel_to_ids) == 1
    tunnel_to_ids = tunnel_to_ids[0]
    if len(application) == 2:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        port = application[1]
        for port_dir in directions:
            flow_id = 'ppp_{0}_{1}_{2}'.format(proto_name, port_dir, port)
            if not controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                controller.app_output_and_resubmit(ovs_node, table_id, higher_priority, proto_name, proto_number, port_dir, port, tunnel_to_ids, table_id + 1)
    elif len(application) == 1:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        flow_id = 'p_{0}'.format(proto_name)
        if not controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
            controller.proto_output_and_resubmit(ovs_node, table_id, lower_priority, proto_name, proto_number, tunnel_to_ids, table_id + 1)

def unmirror_app_from_ids(controller, ovs_node, table_id, application):
    if len(application) == 2:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        port = application[1]
        for port_dir in directions:
            flow_id = 'ppp_{0}_{1}_{2}'.format(proto_name, port_dir, port)
            if controller.flow_exists_in_config(ovs_node, table_id, flow_id):
                controller.delete_config_flow(ovs_node, table_id, flow_id)
            if controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                controller.delete_operational_flow(ovs_node, table_id, flow_id)
    elif len(application) == 1:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        flow_id = 'p_{0}'.format(proto_name)
        if controller.flow_exists_in_config(ovs_node, table_id, flow_id):
            controller.delete_config_flow(ovs_node, table_id, flow_id)
        if controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
            controller.delete_operational_flow(ovs_node, table_id, flow_id)

def mirror_ip_app_to_ids(controller, ovs_node, table_id, lower_priority, higher_priority, ips, application, ovs, ids, tunnels):
    tunnel_to_ids = [tunnel['ofport'] for tunnel in tunnels if tunnel['vm'] == ovs and tunnel['remote'] == ids]
    assert len(tunnel_to_ids) == 1
    tunnel_to_ids = tunnel_to_ids[0]
    if len(application) == 2:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        port = application[1]
        for ip in ips:
            for ip_dir in directions:
                for port_dir in directions:
                    flow_id = 'iippp_{0}_{1}_{2}_{3}_{4}'.format(ip_dir, ip, proto_name, port_dir, port)
                    if not controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                        controller.ip_app_output_and_resubmit(ovs_node, table_id, higher_priority, ip_dir, ip, proto_name, proto_number, port_dir, port, tunnel_to_ids, table_id + 1)
    elif len(application) == 1:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        for ip in ips:
            for ip_dir in directions:
                flow_id = 'iip_{0}_{1}_{2}'.format(ip_dir, ip, proto_name)
                if not controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                    controller.ip_proto_output_and_resubmit(ovs_node, table_id, lower_priority, ip_dir, ip, proto_name, proto_number, tunnel_to_ids, table_id + 1)

def unmirror_ip_app_from_ids(controller, ovs_node, table_id, ips, application):
    if len(application) == 2:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        port = application[1]
        for ip in ips:
            for ip_dir in directions:
                for port_dir in directions:
                    flow_id = 'iippp_{0}_{1}_{2}_{3}_{4}'.format(ip_dir, ip, proto_name, port_dir, port)
                    if controller.flow_exists_in_config(ovs_node, table_id, flow_id):
                        controller.delete_config_flow(ovs_node, table_id, flow_id)
                    if controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                        controller.delete_operational_flow(ovs_node, table_id, flow_id)
    elif len(application) == 1:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        for ip in ips:
            for ip_dir in directions:
                flow_id = 'iip_{0}_{1}_{2}'.format(ip_dir, ip, proto_name)
                if controller.flow_exists_in_config(ovs_node, table_id, flow_id):
                    controller.delete_config_flow(ovs_node, table_id, flow_id)
                if controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                    controller.delete_operational_flow(ovs_node, table_id, flow_id)

def block_ip_app(controller, ovs_node, table_id, lower_priority, higher_priority, ips, application):
    if len(application) == 2:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        port = application[1]
        for ip in ips:
            for ip_dir in directions:
                for port_dir in directions:
                    flow_id = 'iippp_{0}_{1}_{2}_{3}_{4}'.format(ip_dir, ip, proto_name, port_dir, port)
                    if not controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                        controller.ip_app_drop(ovs_node, table_id, higher_priority, ip_dir, ip, proto_name, proto_number, port_dir, port)
    elif len(application) == 1:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        for ip in ips:
            for ip_dir in directions:
                flow_id = 'iip_{0}_{1}_{2}'.format(ip_dir, ip, proto_name)
                if not controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                    controller.ip_proto_drop(ovs_node, table_id, lower_priority, ip_dir, ip, proto_name, proto_number)

def unblock_ip_app(controller, ovs_node, table_id, ips, application):
    if len(application) == 2:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        port = application[1]
        for ip in ips:
            for ip_dir in directions:
                for port_dir in directions:
                    flow_id = 'iippp_{0}_{1}_{2}_{3}_{4}'.format(ip_dir, ip, proto_name, port_dir, port)
                    if controller.flow_exists_in_config(ovs_node, table_id, flow_id):
                        controller.delete_config_flow(ovs_node, table_id, flow_id)
                    if controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                        controller.delete_operational_flow(ovs_node, table_id, flow_id)
    elif len(application) == 1:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        for ip in ips:
            for ip_dir in directions:
                flow_id = 'iip_{0}_{1}_{2}'.format(ip_dir, ip, proto_name)
                if controller.flow_exists_in_config(ovs_node, table_id, flow_id):
                    controller.delete_config_flow(ovs_node, table_id, flow_id)
                if controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                    controller.delete_operational_flow(ovs_node, table_id, flow_id)

if __name__ == '__main__':

    # params

    env_idx = 0
    ids_id = 1
    ids_name = 'ids_{0}_{1}'.format(env_idx, ids_id)
    remote_ips = ['18.221.219.4']
    app1 = ('tcp', 80)
    app2 = ('udp',)

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
    assert (len(ids_nodes) + 4) <= ntables

    # controller

    controller_vm = [vm for vm in vms if vm['role'] == 'sdn']
    assert len(controller_vm) == 1
    controller_name = controller_vm[0]['vm']
    controller_ip = controller_vm[0]['ip']

    if controller_name == 'odl':
        controller = Odl(controller_ip)

    # action test

    mirror_app_to_ids(controller, ovs_node, ids_tables[ids_id], priorities['lower'], priorities['medium'], app1, ovs_vm['vm'], ids_name, tunnels)
    mirror_app_to_ids(controller, ovs_node, ids_tables[ids_id], priorities['lower'], priorities['medium'], app2, ovs_vm['vm'], ids_name, tunnels)
    mirror_ip_app_to_ids(controller, ovs_node, ids_tables[ids_id], priorities['higher'], priorities['highest'], remote_ips, app1, ovs_vm['vm'], ids_name, tunnels)
    mirror_ip_app_to_ids(controller, ovs_node, ids_tables[ids_id], priorities['higher'], priorities['highest'], remote_ips, app2, ovs_vm['vm'], ids_name, tunnels)
    block_ip_app(controller, ovs_node, block_table, priorities['higher'], priorities['highest'], remote_ips, app1)
    block_ip_app(controller, ovs_node, block_table, priorities['higher'], priorities['highest'], remote_ips, app2)

    sleep(10)

    unmirror_app_from_ids(controller, ovs_node, ids_tables[ids_id], app1)
    unmirror_app_from_ids(controller, ovs_node, ids_tables[ids_id], app2)
    unmirror_ip_app_from_ids(controller, ovs_node, ids_tables[ids_id], remote_ips, app1)
    unmirror_ip_app_from_ids(controller, ovs_node, ids_tables[ids_id], remote_ips, app2)
    unblock_ip_app(controller, ovs_node, block_table, remote_ips, app1)
    unblock_ip_app(controller, ovs_node, block_table, remote_ips, app2)