import json

from common.odl import Odl
from config import *
from common.utils import ip_proto, bit_list_to_dec
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
            else:
                break
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
            else:
                break
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
            does_flow_exist = False
            for ip_dir in directions:
                for port_dir in directions:
                    flow_id = 'iippp_{0}_{1}_{2}_{3}_{4}'.format(ip_dir, ip, proto_name, port_dir, port)
                    if not controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                        controller.ip_app_output_and_resubmit(ovs_node, table_id, higher_priority, ip_dir, ip, proto_name, proto_number, port_dir, port, tunnel_to_ids, table_id + 1)
                    else:
                        does_flow_exist = True
                        break
                if does_flow_exist:
                    break
    elif len(application) == 1:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        for ip in ips:
            does_flow_exist = False
            for ip_dir in directions:
                flow_id = 'iip_{0}_{1}_{2}'.format(ip_dir, ip, proto_name)
                if not controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                    controller.ip_proto_output_and_resubmit(ovs_node, table_id, lower_priority, ip_dir, ip, proto_name, proto_number, tunnel_to_ids, table_id + 1)
                else:
                    does_flow_exist = True
                    break
                if does_flow_exist:
                    break

def unmirror_ip_app_from_ids(controller, ovs_node, table_id, ips, application):
    if len(application) == 2:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        port = application[1]
        for ip in ips:
            does_flow_exist = False
            for ip_dir in directions:
                for port_dir in directions:
                    flow_id = 'iippp_{0}_{1}_{2}_{3}_{4}'.format(ip_dir, ip, proto_name, port_dir, port)
                    if controller.flow_exists_in_config(ovs_node, table_id, flow_id):
                        controller.delete_config_flow(ovs_node, table_id, flow_id)
                    if controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                        controller.delete_operational_flow(ovs_node, table_id, flow_id)
                    else:
                        does_flow_exist = True
                        break
                if does_flow_exist == True:
                    break
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
                else:
                    break

def forward_dscp_to_ids(controller, ovs_node, table_id, priority, dscp, tunnel_to_ids):
    flow_id = 'd_{0}'.format(dscp)
    if not controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
        controller.dscp_output(ovs_node, table_id, priority, dscp, tunnel_to_ids)

def unforward_dscp_from_ids(controller, ovs_node, table_id, dscp):
    flow_id = 'd_{0}'.format(dscp)
    if controller.flow_exists_in_config(ovs_node, table_id, flow_id):
        controller.delete_config_flow(ovs_node, table_id, flow_id)
    if controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
        controller.delete_operational_flow(ovs_node, table_id, flow_id)

def block_dscp(controller, ovs_node, table_id, priority, dscp):
    flow_id = 'd_{0}'.format(dscp)
    if not controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
        controller.dscp_drop(ovs_node, table_id, priority, dscp)

def unblock_dscp(controller, ovs_node, table_id, dscp):
    flow_id = 'd_{0}'.format(dscp)
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
            does_flow_exist = False
            for ip_dir in directions:
                for port_dir in directions:
                    flow_id = 'iippp_{0}_{1}_{2}_{3}_{4}'.format(ip_dir, ip, proto_name, port_dir, port)
                    if not controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                        controller.ip_app_drop(ovs_node, table_id, higher_priority, ip_dir, ip, proto_name, proto_number, port_dir, port)
                    else:
                        does_flow_exist = True
                    if does_flow_exist:
                        break
                if does_flow_exist:
                    break
    elif len(application) == 1:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        for ip in ips:
            does_flow_exist = False
            for ip_dir in directions:
                flow_id = 'iip_{0}_{1}_{2}'.format(ip_dir, ip, proto_name)
                if not controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                    controller.ip_proto_drop(ovs_node, table_id, lower_priority, ip_dir, ip, proto_name, proto_number)
                else:
                    does_flow_exist = True
                if does_flow_exist:
                    break
            if does_flow_exist:
                break

def unblock_ip_app(controller, ovs_node, table_id, ips, application):
    if len(application) == 2:
        proto_name = application[0]
        _, proto_number = ip_proto(proto_name)
        port = application[1]
        for ip in ips:
            does_flow_exist = False
            for ip_dir in directions:
                for port_dir in directions:
                    flow_id = 'iippp_{0}_{1}_{2}_{3}_{4}'.format(ip_dir, ip, proto_name, port_dir, port)
                    if controller.flow_exists_in_config(ovs_node, table_id, flow_id):
                        controller.delete_config_flow(ovs_node, table_id, flow_id)
                    if controller.flow_exists_in_operational(ovs_node, table_id, flow_id):
                        controller.delete_operational_flow(ovs_node, table_id, flow_id)
                    else:
                        does_flow_exist = True
                        break
                if does_flow_exist == True:
                    break
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
                else:
                    break

if __name__ == '__main__':

    # params

    env_idx = 0
    ids_ids = [0, 1, 2]
    dscp_to_idss = [[0, 0, 0], [1, 0, 0], [1, 1, 0]]
    dscp_to_block = [1, 1, 1]
    test_reverse_actions = False

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

    # tunnels

    tunnel_to_idss = []
    for ids_id in ids_ids:
        ids_name = 'ids_{0}_{1}'.format(env_idx, ids_id)
        tunnel_to_ids = [ofport['ofport'] for ofport in ofports if ofport['type'] == 'vxlan' and ofport['vm'] == ovs_vm['vm'] and ofport['remote'] == ids_name]
        assert len(tunnel_to_ids) == 1
        tunnel_to_ids = tunnel_to_ids[0]
        tunnel_to_idss.append(tunnel_to_ids)

    # controller

    controller_vm = [vm for vm in vms if vm['role'] == 'sdn']
    assert len(controller_vm) == 1
    controller_name = controller_vm[0]['vm']
    controller_ip = controller_vm[0]['ip']
    controller = Odl(controller_ip)

    # mirror and block

    for i, (dscp, tunnel_to_ids) in enumerate(zip(dscp_to_idss, tunnel_to_idss)):
        forward_dscp_to_ids(controller, ovs_node, ids_tables[i], priorities['lower'], bit_list_to_dec(dscp), tunnel_to_ids)
    block_dscp(controller, ovs_node, block_table, priorities['lower'], bit_list_to_dec(dscp_to_block))

    if test_reverse_actions:

        # sleep

        sleep_time = 10
        print(f'Sleeping for {sleep_time} seconds...')
        sleep(sleep_time)

        # unmirror and unblock

        for i, (dscp, tunnel_to_ids) in enumerate(zip(dscp_to_idss, tunnel_to_idss)):
            unforward_dscp_from_ids(controller, ovs_node, ids_tables[i], bit_list_to_dec(dscp))
        unblock_dscp(controller, ovs_node, block_table, bit_list_to_dec(dscp_to_block))