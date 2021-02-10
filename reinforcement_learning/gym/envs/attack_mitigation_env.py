import numpy as np
import requests
from reinforcement_learning.gym import spaces

from time import sleep, time
from common.odl import Odl
from common.docker import exec_cmd_on_container, kill_process_on_container
from common.utils import gateway, nat_ip, ip_ptoto, mac_hex, ip_hex, network

class AttackMitigationEnv():

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
    higher_priority = 3

    def __init__(self, vms, tunnels, nodes, containers, traffic, port=5000, n_models=4, n_thrs=5, attacker_name='attacker', tthreshold=60):

        self.vms = vms
        self.tunnels = tunnels
        self.nodes = nodes
        self.containers = containers
        self.traffic = traffic

        self.tstart = None
        self.tthreshold = tthreshold
        self._set_controller()

        self.ids_vms = [vm for vm in vms if vm['vm'].startswith('ids')]
        self.port = port
        self._set_ids_labels()

        #self._set_docker_iptables()
        #self._set_docker_servers()

        self._get_apps()
        self.n_hosts = len(self.internal_hosts)
        self.n_apps = len(self.apps)
        self.mon_vm = [vm for vm in vms if vm['vm'].startswith('mon')][0]

        self.n_models = n_models
        self.n_thrs = n_thrs

        self.n_redirect_actions = (self.n_hosts + 1) * (self.n_apps + len(self.external_ports)) * self.n_dscp * self.n_ids
        self.n_block_actions = (self.n_hosts + 1) * (self.n_apps + len(self.external_ports)) * self.n_dscp
        self.n_ids_actions = self.n_models * self.n_thrs

        self.attackers = []
        for container in containers:
            if attacker_name in container['name']:
                self.attackers.append(container['ip'])
        self.n_attackers = len(self.attackers)
        self.n_normal = len(self.containers) - len(self.attackers)

        self.observation_space = spaces.Box(low=0, high=np.inf, shape=(self.n_hosts + 1, self.n_apps + len(self.external_ports), 4), dtype=np.float32)
        self.action_space = spaces.Discrete(self.n_redirect_actions + self.n_block_actions + self.n_ids_actions + 1)
        print(self.action_space)

    def _set_controller(self):
        controller_vm = [vm for vm in self.vms if vm['vm'] == 'odl']
        assert len(controller_vm) == 1
        controller_ip = controller_vm[0]['ip']
        self.controller = Odl(controller_ip)

    def _clean_tables(self):

        # delete flows if there are any

        for node in self.nodes.values():
            tables = self.controller.find_tables(node)
            for table in tables:
                flows = self.controller.find_flows(node, table)
                for flow in flows:
                    self.controller.delete_flow(node, table, flow)


        # protocols

        arp_proto = 2054
        ip_proto = 2048

        # default flows

        for node in self.nodes.values():
            self.controller.resubmit_proto(node, self.default_table, self.low_priority, arp_proto, self.arp_table)
            self.controller.resubmit_proto(node, self.default_table, self.low_priority, ip_proto, self.ip_src_table)
            self.controller.resubmit_proto(node, self.ip_src_table, self.low_priority, ip_proto, self.ip_ids_table)
            self.controller.resubmit_proto(node, self.ip_ids_table, self.low_priority, ip_proto, self.ip_dpi_table)
            self.controller.resubmit_proto(node, self.ip_dpi_table, self.low_priority, ip_proto, self.ip_fw_table)
            self.controller.resubmit_proto(node, self.ip_fw_table, self.low_priority, ip_proto, self.ip_mon_table)

        # subnets and gateways

        subnets = []
        gateways = []
        for container in self.containers:
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
            for node in self.nodes.keys():
                if node in vms:
                    ext = False
                    break
            if ext:
                ext_subnets.append(network(gw_ip))
                for vm in vms:
                    assert vm not in self.nodes.keys()
            else:
                for vm in vms:
                    assert vm in self.nodes.keys()
        ext_subnets = list(set(ext_subnets))

        # arp auto-responder

        for gw_ip in gateways:
            self.controller.arp_auto_reply(self.nodes['gw'], self.arp_table, self.low_priority, ip_hex(gw_ip), mac_hex(gw_ip))

        # add arp flows

        for subnet, gw_ip in zip(subnets, gateways):

            # arp destination flows

            for container in subnet:
                if container['vm'] in self.nodes.keys():
                    self.controller.arp_output(self.nodes[container['vm']], self.arp_table, self.low_priority, container['ip'], container['ofport'])

            # tunnel to gw

            vms = set(list([container['vm'] for container in subnet if container['vm'] in self.nodes.keys()]))
            for vm in vms:
                vxlan = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == vm and tunnel['remote'] == 'gw']
                assert len(vxlan) == 1
                vxlan = vxlan[0]
                self.controller.arp_output(self.nodes[vm], self.arp_table, self.low_priority, gw_ip, vxlan)

            # tunnel to another ovs

            for container1 in subnet:
                for container2 in subnet:
                    if container1['vm'] != container2['vm']:
                        vxlan = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == container1['vm'] and tunnel['remote'] == container2['vm']]
                        assert len(vxlan) == 1
                        vxlan = vxlan[0]
                        self.controller.arp_output(self.nodes[container1['vm']], 1, 0, container2['ip'], vxlan)

        # add ip src flows

        for container in self.containers:
            if container['vm'] in self.nodes.keys():
                vxlan = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == container['vm'] and tunnel['remote'] == 'mon']
                assert len(vxlan) == 1
                vxlan = vxlan[0]
                self.controller.ip_src_output_and_resubmit(self.nodes[container['vm']], self.ip_src_table, self.high_priority, container['ip'], vxlan, self.ip_ids_table)

        for ext_subnet in ext_subnets:
            vxlan = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == 'mon']
            assert len(vxlan) == 1
            vxlan = vxlan[0]
            self.controller.ip_src_output_and_resubmit(self.nodes['gw'], self.ip_src_table, self.high_priority, ext_subnet, vxlan, self.ip_ids_table, mask=24)

        # add ip mon flows in the same internal subnet

        for subnet, gw_ip in zip(subnets, gateways):

            # same ovs

            for container in subnet:
                if container['vm'] in self.nodes.keys():
                    vxlan = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == container['vm'] and tunnel['remote'] == 'mon']
                    assert len(vxlan) == 1
                    vxlan = vxlan[0]
                    self.controller.ip_dst_mod_ecn_and_output_and_resubmit(self.nodes[container['vm']], self.ip_mon_table, self.high_priority, container['ip'], 0, 2, vxlan, self.ip_dst_table)
                    self.controller.ip_dst_mod_ecn_and_output_and_resubmit(self.nodes[container['vm']], self.ip_mon_table, self.high_priority, container['ip'], 1, 3, vxlan, self.ip_dst_table)

            # another ovs

            for container1 in subnet:
                for container2 in subnet:
                    if container1['vm'] != container2['vm']:
                        vxlan = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == container1['vm'] and tunnel['remote'] == container2['vm']]
                        assert len(vxlan) == 1
                        vxlan = vxlan[0]
                        self.controller.ip_dst_output(self.nodes[container1['vm']], self.ip_mon_table, self.high_priority, container2['ip'], vxlan)

        # add ip mon flows to a different subnet

        for subnet1 in subnets:
            for subnet2, gw_ip in zip(subnets, gateways):
                if subnet1 != subnet2:
                    for container in subnet1:
                        if container['vm'] in self.nodes.keys():
                            vxlan = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == container['vm'] and tunnel['remote'] == 'gw']
                            assert len(vxlan) == 1
                            vxlan = vxlan[0]
                            self.controller.ip_dst_output(self.nodes[container['vm']], self.ip_mon_table, self.high_priority, network(gw_ip), vxlan, mask=24)

        # add ip mon flows to an external subnet

        # to outside

        for ext_subnet in ext_subnets:
            vxlan = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == 'mon']
            assert len(vxlan) == 1
            vxlan = vxlan[0]
            self.controller.ip_dst_mod_ecn_and_output_and_resubmit(self.nodes['gw'], self.ip_mon_table, self.low_priority, ext_subnet, 0, 2, vxlan, self.ip_dst_table, mask=24)
            self.controller.ip_dst_mod_ecn_and_output_and_resubmit(self.nodes['gw'], self.ip_mon_table, self.low_priority, ext_subnet, 1, 3, vxlan, self.ip_dst_table, mask=24)

        # from outside

        for subnet in subnets:
            for container in subnet:
                if container['vm'] in self.nodes.keys():
                    vxlan = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['remote'] == container['vm'] and tunnel['vm'] == 'gw']
                    assert len(vxlan) == 1
                    vxlan = vxlan[0]
                    for ext_subnet in ext_subnets:
                        gw_ip = gateway(ext_subnet)
                        self.controller.ip_dst_mod_mac_and_output(self.nodes['gw'], self.ip_mon_table, self.high_priority, container['ip'], mac_hex(gw_ip)[0], mac_hex(container['ip'])[0], vxlan)

        # add ip dst flows

        for subnet, gw_ip in zip(subnets, gateways):
            for container in subnet:
                if container['vm'] in self.nodes.keys():
                    self.controller.ip_dst_mod_ecn_and_output(self.nodes[container['vm']], self.ip_dst_table, self.high_priority, container['ip'], 2, 0, container['ofport'])
                    self.controller.ip_dst_mod_ecn_and_output(self.nodes[container['vm']], self.ip_dst_table, self.high_priority, container['ip'], 3, 1, container['ofport'])

        for subnet1, gw_ip in zip(subnets, gateways):
            for subnet2 in subnets:
                if subnet2 != subnet1:
                    for container in subnet2:
                        if container['vm'] not in self.nodes.keys():
                            vxlan = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['remote'] == container['vm'] and tunnel['vm'] == 'gw']
                            assert len(vxlan) == 1
                            vxlan = vxlan[0]
                            self.controller.ip_dst_mod_ecn_and_mac_and_output(self.nodes['gw'], self.ip_dst_table, self.high_priority, container['ip'], 2, mac_hex(gw_ip)[0], 0, mac_hex(container['ip'])[0], vxlan)
                            self.controller.ip_dst_mod_ecn_and_mac_and_output(self.nodes['gw'], self.ip_dst_table, self.high_priority, container['ip'], 3, mac_hex(gw_ip)[0], 1, mac_hex(container['ip'])[0], vxlan)

    def _action_mapper(self, i):

        if i < self.n_redirect_actions:
            action_array = np.zeros(self.n_redirect_actions)
            action_array[i] = 1
            action_array = action_array.reshape(self.n_hosts + 1, self.n_apps + len(self.external_ports), self.n_dscp, self.n_ids)
            host, app, dscp, ids = np.where(action_array == 1)
            if host[0] < self.n_hosts:
                src = [self.internal_hosts[host[0]]]
            else:
                src = self.external_hosts
            if app[0] < self.n_apps:
                dst_, app_ = self.apps[app[0]].split(':')
                dst = [dst_]
                app = int(app_)
            else:
                dst = self.external_hosts
                app = self.external_ports[app[0] - self.n_apps]
            dscp = dscp[0]
            ids = ids[0] + 1
            action_fun = self._redirect_action
            args = (src, dst, app, dscp, ids)
        elif i < self.n_redirect_actions + self.n_block_actions:
            i = i - self.n_redirect_actions
            action_array = np.zeros(self.n_block_actions)
            action_array[i] = 1
            action_array = action_array.reshape(self.n_hosts + 1, self.n_apps + len(self.external_ports), self.n_dscp)
            host, app, dscp = np.where(action_array == 1)
            if host[0] < self.n_hosts:
                src = [self.internal_hosts[host[0]]]
            else:
                src = self.external_hosts
            if app[0] < self.n_apps:
                dst_, app_ = self.apps[app[0]].split(':')
                dst = [dst_]
                app = int(app_)
            else:
                dst = self.external_hosts
                app = self.external_ports[app[0] - self.n_apps]
            dscp = dscp[0]
            action_fun = self._drop_action
            args = (src, dst, app, dscp)
        elif i < self.n_redirect_actions + self.n_block_actions + self.n_ids_actions:
            i = i - self.n_redirect_actions - self.n_block_actions
            action_array = np.zeros(self.n_ids * self.n_models * self.n_thrs)
            action_array[i] = 1
            action_array = action_array.reshape(self.n_ids, self.n_models, self.n_thrs)
            ids, model, thr = np.where(action_array == 1)
            action_fun = self._model_action
            args = (int(ids[0]), int(model[0]), int(thr[0]))
        else:
            action_fun = lambda *args: None
            args = ()
        return action_fun, args

    def _prepare_action_tensor(self):
        d = self.n_dscp * (self.n_ids + 1)
        self.actions_taken = np.zeros((self.n_hosts + 1, self.n_apps + len(self.external_ports), d))

    def _update_action_tensor(self, i):
        d = self.n_dscp * (self.n_ids + 1)
        n = (self.n_hosts + 1) * (self.n_apps + len(self.external_ports))
        action_array = np.zeros(n)
        action_array[i] = 1
        action_array = action_array.reshape(self.n_hosts + 1, self.n_apps + len(self.external_ports), d)
        i1, i2, i3 = np.where(action_array == 1)
        self.actions_taken[i1[0], i2[0], i3[0]] = 1

    def _get_apps(self):
        self.internal_hosts = []
        self.apps = []
        self.external_hosts = []
        self.external_ports = []
        for container in self.containers:
            if container['vm'] in self.nodes.keys():
                self.internal_hosts.append(container['ip'])
                for app_port in container['applications']:
                    app = '{0}:{1}'.format(container['ip'], app_port)
                    if app not in self.apps:
                        self.apps.append(app)
            else:
                self.external_hosts.append(container['ip'])
                for app_port in container['applications']:
                    if app_port not in self.external_ports:
                        self.external_ports.append(app_port)

        print(self.internal_hosts)
        print(self.apps)
        print(self.external_hosts)
        print(self.external_ports)

    def _get_subnet_traffic(self):
        url = 'http://{0}:{1}/flows'.format(self.mon_vm['mgmt'], self.port)
        jdata = requests.get(url).json()
        n = len(self.subnets)
        m = len(self.applications)
        in_counts = np.zeros((m + 1, n, n))
        out_counts = np.zeros((m + 1, n, n))
        for key in jdata.keys():
            for item in jdata[key]:
                src = item[0]
                if gateway(src) in self.gateways:
                    src_subnet_idx = self.gateways.index(gateway(src))
                else:
                    src_subnet_idx = n - 1
                dst = item[2]
                if gateway(dst) in self.gateways:
                    dst_subnet_idx = self.gateways.index(gateway(dst))
                else:
                    dst_subnet_idx = n - 1
                sport = item[1]
                dport = item[3]
                if sport in self.applications:
                    app_idx = self.applications.index(sport)
                elif dport in self.applications:
                    app_idx = self.applications.index(dport)
                else:
                    app_idx = m
                value = item[5]
                if key.startswith('in'):
                    in_counts[app_idx, src_subnet_idx, dst_subnet_idx] = value
                elif key.startswith('out'):
                    out_counts[app_idx, src_subnet_idx, dst_subnet_idx] = value

    def _get_traffic(self):
        url = 'http://{0}:{1}/flows'.format(self.mon_vm['mgmt'], self.port)
        jdata = requests.get(url).json()
        counts = np.zeros((self.n_hosts + 1, self.n_apps + len(self.external_ports), 4))
        pkts_in = np.zeros(self.n_attackers + 1)
        pkts_out = np.zeros(self.n_attackers + 1)
        for key in jdata.keys():
            for item in jdata[key]:
                src, sport, dst, dport = item[0:4]
                sapp = '{0}:{1}'.format(src, sport)
                dapp = '{0}:{1}'.format(dst, dport)
                if sapp in self.apps:
                    app_idx = self.apps.index(sapp)
                    dir_idx = 1
                    if dst in self.internal_hosts:
                        host_idx = self.internal_hosts.index(dst)
                    else:
                        host_idx = self.n_hosts
                elif dapp in self.apps:
                    app_idx = self.apps.index(dapp)
                    dir_idx = 0
                    if src in self.internal_hosts:
                        host_idx = self.internal_hosts.index(src)
                    else:
                        host_idx = self.n_hosts
                elif src in self.external_hosts and sport in self.external_ports and dst in self.internal_hosts:
                        host_idx = self.internal_hosts.index(dst)
                        app_idx = self.n_apps + self.external_ports.index(sport)
                        dir_idx = 1
                elif dst in self.external_hosts and dport in self.external_ports and src in self.internal_hosts:
                        host_idx = self.internal_hosts.index(src)
                        app_idx = self.n_apps + self.external_ports.index(dport)
                        dir_idx = 0
                else:
                    print(src, sport, dst, dport)
                value = item[5]
                if src in self.attackers:
                    idx = self.attackers.index(src)
                elif dst in self.attackers:
                    idx = self.attackers.index(dst)
                else:
                    idx = -1
                if key.startswith('in'):
                    counts[host_idx, app_idx, dir_idx] = value
                    pkts_in[idx] += value
                elif key.startswith('out'):
                    counts[host_idx, app_idx, 2 + dir_idx] = value
                    pkts_out[idx] += value
        self.obs_traffic = np.array(counts)
        self.n_normal_in_avg =  pkts_in[-1] / self.n_normal
        self.n_normal_out_avg = pkts_out[-1] = self.n_normal
        self.n_attack_in = np.array(pkts_in[:-1])
        self.n_attack_out = np.array(pkts_out[:-1])

    def _set_docker_iptables(self):
        cmd = 'iptables -A OUTPUT -p tcp -o eth0 --tcp-flags RST RST -j DROP'
        for item in self.traffic:
            c_name = item['name']
            c_vm_name = [container['vm'] for container in self.containers if container['name'] == c_name]
            assert len(c_vm_name) == 1
            c_vm_name = c_vm_name[0]
            c_vm = [vm for vm in self.vms if vm['vm'] == c_vm_name]
            assert len(c_vm) == 1
            c_vm = c_vm[0]
            exec_cmd_on_container(c_vm, c_name, cmd)

    def _set_ids_labels(self, nmax=6):
        self.n_ids = np.minimum(len(self.ids_vms), nmax)
        self.n_dscp = 2 ** self.n_ids
        for i in range(self.n_ids):
            ids_vm = self.ids_vms[i]
            dscp_url = 'http://{0}:{1}/dscp'.format(ids_vm['mgmt'], self.port)
            requests.post(dscp_url, json={'dscp': i})

    def _stop_traffic(self):
        for item in self.traffic:
            if 'server' in item.keys():
                c_name = item['name']
                c_vm_name = [container['vm'] for container in self.containers if container['name'] == c_name]
                assert len(c_vm_name) == 1
                c_vm_name = c_vm_name[0]
                c_vm = [vm for vm in self.vms if vm['vm'] == c_vm_name]
                assert len(c_vm) == 1
                c_vm = c_vm[0]
                kill_process_on_container(c_vm, c_name, 'python3')

    def _start_traffic(self):
        for item in self.traffic:
            if item['type'] == 'server':
                c_name = item['name']
                c_vm_name = [container['vm'] for container in self.containers if container['name'] == c_name]
                assert len(c_vm_name) == 1
                c_vm_name = c_vm_name[0]
                c_vm = [vm for vm in self.vms if vm['vm'] == c_vm_name]
                assert len(c_vm) == 1
                c_vm = c_vm[0]
                cmd = 'python3 server.py -t {0}'.format(item['label'])
                exec_cmd_on_container(c_vm, c_name, cmd)
        for item in self.traffic:
            if item['type'] == 'client':
                c_name = item['name']
                c_vm_name = [container['vm'] for container in self.containers if container['name'] == c_name]
                assert len(c_vm_name) == 1
                c_vm_name = c_vm_name[0]
                c_vm = [vm for vm in self.vms if vm['vm'] == c_vm_name]
                assert len(c_vm) == 1
                c_vm = c_vm[0]
                cmd = 'python3 client.py -t {0} -r {1}'.format(item['label'], item['server'])
                exec_cmd_on_container(c_vm, c_name, cmd)

    def _redirect_action(self, source_list, destination_list, application, dscp, idsi, protocol='tcp'):

        sport = [application, 'source']
        dport = [application, 'destination']
        proto = ip_ptoto(protocol)
        ids = 'ids{0}'.format(idsi)
        ids_br_mac = ':'.join([hex(int(self.nodes[ids].split(':')[1]))[i:i + 2] for i in range(2, 16, 2)][:-1])

        for source in source_list:
            for destination in destination_list:

                container_s = [container for container in self.containers if container['ip'] == source]
                assert len(container_s) == 1
                container_s = container_s[0]
                container_d = [container for container in self.containers if container['ip'] == destination]
                assert len(container_d) == 1
                container_d = container_d[0]

                ip_s = container_s['ip']
                ip_d = container_d['ip']
                ip_s_gw = gateway(ip_s)
                ip_d_gw = gateway(ip_d)
                ip_s_nat = nat_ip(ip_s, prefix='1{0}'.format(str(idsi)))
                ip_s_nat_gw = gateway(ip_s_nat)
                ip_d_nat = nat_ip(ip_d, prefix='1{0}'.format(str(idsi)))
                ip_d_nat_gw = gateway(ip_d_nat)
                mac_s = mac_hex(ip_s)[0]
                mac_d = mac_hex(ip_d)[0]
                mac_s_gw = mac_hex(ip_s_gw)[0]
                mac_d_gw = mac_hex(ip_d_gw)[0]

                # ovs arp

                if container_s['vm'] in self.nodes.keys():
                    tunnel_to_ids = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == container_s['vm'] and tunnel['remote'] == ids]
                    assert len(tunnel_to_ids) == 1
                    tunnel_to_ids = tunnel_to_ids[0]
                    self.controller.arp_spa_tpa_mod_tpa_and_output(self.nodes[container_s['vm']], self.arp_table, self.high_priority, ip_s_nat_gw, ip_s_nat, ip_hex(ip_s), container_s['ofport'])
                    self.controller.arp_spa_tpa_mod_spa_and_output(self.nodes[container_s['vm']], self.arp_table, self.high_priority, ip_s, ip_s_nat_gw, ip_hex(ip_s_nat), tunnel_to_ids)
                else:
                    tunnel_to_ids = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == ids]
                    assert len(tunnel_to_ids) == 1
                    tunnel_to_ids = tunnel_to_ids[0]
                    vxlan = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == container_s['vm']]
                    assert len(vxlan) == 1
                    vxlan = vxlan[0]
                    self.controller.arp_spa_tpa_mod_tpa_and_output(self.nodes['gw'], self.arp_table, self.high_priority, ip_s_nat_gw, ip_s_nat, ip_hex(ip_s), vxlan)
                    self.controller.arp_spa_tpa_mod_spa_and_output(self.nodes['gw'], self.arp_table, self.high_priority, ip_s, ip_s_nat_gw, ip_hex(ip_s_nat), tunnel_to_ids)

                if container_d['vm'] in self.nodes.keys():
                    tunnel_to_ids = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == container_d['vm'] and tunnel['remote'] == ids]
                    assert len(tunnel_to_ids) == 1
                    tunnel_to_ids = tunnel_to_ids[0]
                    self.controller.arp_spa_tpa_mod_tpa_and_output(self.nodes[container_d['vm']], self.arp_table, self.high_priority, ip_d_nat_gw, ip_d_nat, ip_hex(ip_d), container_d['ofport'])
                    self.controller.arp_spa_tpa_mod_spa_and_output(self.nodes[container_d['vm']], self.arp_table, self.high_priority, ip_d, ip_d_nat_gw, ip_hex(ip_d_nat), tunnel_to_ids)
                else:
                    tunnel_to_ids = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == ids]
                    assert len(tunnel_to_ids) == 1
                    tunnel_to_ids = tunnel_to_ids[0]
                    vxlan = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == container_d['vm']]
                    assert len(vxlan) == 1
                    vxlan = vxlan[0]
                    self.controller.arp_spa_tpa_mod_tpa_and_output(self.nodes['gw'], self.arp_table, self.high_priority, ip_d_nat_gw, ip_d_nat, ip_hex(ip_d), vxlan)
                    self.controller.arp_spa_tpa_mod_spa_and_output(self.nodes['gw'], self.arp_table, self.high_priority, ip_d, ip_d_nat_gw, ip_hex(ip_d_nat), tunnel_to_ids)

                # ids arp

                if container_s['vm'] in self.nodes.keys():
                    tunnel_to_src = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['remote'] == container_s['vm'] and tunnel['vm'] == ids]
                    assert len(tunnel_to_src) == 1
                    tunnel_to_src = tunnel_to_src[0]
                else:
                    tunnel_to_src = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['remote'] == 'gw' and tunnel['vm'] == ids]
                    assert len(tunnel_to_src) == 1
                    tunnel_to_src = tunnel_to_src[0]
                self.controller.arp_output(self.nodes[ids], self.arp_table, self.high_priority, ip_s_nat, tunnel_to_src)

                if container_d['vm'] in self.nodes.keys():
                    tunnel_to_dst = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['remote'] == container_d['vm'] and tunnel['vm'] == ids]
                    assert len(tunnel_to_dst) == 1
                    tunnel_to_dst = tunnel_to_dst[0]
                else:
                    tunnel_to_dst = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['remote'] == 'gw' and tunnel['vm'] == ids]
                    assert len(tunnel_to_dst) == 1
                    tunnel_to_dst = tunnel_to_dst[0]
                self.controller.arp_output(self.nodes[ids], self.arp_table, self.high_priority, ip_d_nat, tunnel_to_dst)

                self.controller.arp_output(self.nodes[ids], self.arp_table, self.high_priority, ip_s_nat_gw, 'LOCAL')
                if ip_d_nat_gw != ip_s_nat_gw:
                    self.controller.arp_output(self.nodes[ids], self.arp_table, self.high_priority, ip_d_nat_gw, 'LOCAL')

                # ids ip

                self.controller.ip_src_dst_port_mod_mac_and_output(self.nodes[ids], self.ip_ids_table, self.high_priority, ip_s_nat, ip_d_nat, proto, dport, ids_br_mac, 'LOCAL')
                self.controller.ip_src_dst_port_mod_mac_and_output(self.nodes[ids], self.ip_ids_table, self.high_priority, ip_d_nat, ip_s_nat, proto, sport, ids_br_mac, 'LOCAL')
                self.controller.ip_src_dst_port_mac_output(self.nodes[ids], self.ip_ids_table, self.higher_priority, ip_s_nat, ip_d_nat, proto, dport, ids_br_mac, tunnel_to_src)
                self.controller.ip_src_dst_port_mac_output(self.nodes[ids], self.ip_ids_table, self.higher_priority, ip_d_nat, ip_s_nat, proto, sport, ids_br_mac, tunnel_to_dst)

                # ovs ip

                if container_s['vm'] in self.nodes.keys() and container_d['vm'] in self.nodes.keys():

                    # request

                    tunnel_to_ids = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == container_s['vm'] and tunnel['remote'] == ids]
                    assert len(tunnel_to_ids) == 1
                    tunnel_to_ids = tunnel_to_ids[0]
                    self.controller.ip_src_dst_port_dscp_mod_src_dst_output(self.nodes[container_s['vm']], self.ip_ids_table, self.high_priority, ip_s, ip_d, proto, dport, dscp, ip_s_nat, ip_d_nat, tunnel_to_ids)
                    self.controller.ip_src_dst_port_mod_src_dst_mac_and_resubmit(self.nodes[container_s['vm']], self.ip_ids_table, self.high_priority, ip_s_nat, ip_d_nat, proto, dport, ip_s, ip_d, mac_s, self.ip_dpi_table)

                    # reply

                    tunnel_to_ids = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == container_d['vm'] and tunnel['remote'] == ids]
                    assert len(tunnel_to_ids) == 1
                    tunnel_to_ids = tunnel_to_ids[0]
                    self.controller.ip_src_dst_port_dscp_mod_src_dst_output(self.nodes[container_d['vm']], self.ip_ids_table, self.high_priority, ip_d, ip_s, proto, sport, dscp, ip_d_nat, ip_s_nat, tunnel_to_ids)
                    self.controller.ip_src_dst_port_mod_src_dst_mac_and_resubmit(self.nodes[container_d['vm']], self.ip_ids_table, self.high_priority, ip_d_nat, ip_s_nat, proto, sport, ip_d, ip_s, mac_d, self.ip_dpi_table)

                elif container_s['vm'] in self.nodes.keys() and container_d['vm'] not in self.nodes.keys():

                    # request

                    tunnel_to_ids = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == container_s['vm'] and tunnel['remote'] == ids]
                    assert len(tunnel_to_ids) == 1
                    tunnel_to_ids = tunnel_to_ids[0]
                    self.controller.ip_src_dst_port_dscp_mod_src_dst_output(self.nodes[container_s['vm']], self.ip_ids_table, self.high_priority, ip_s, ip_d, proto, dport, dscp, ip_s_nat, ip_d_nat, tunnel_to_ids)
                    self.controller.ip_src_dst_port_mod_src_dst_macs_and_resubmit(self.nodes[container_s['vm']], self.ip_ids_table, self.high_priority, ip_s_nat, ip_d_nat, proto, dport, ip_s, ip_d, mac_s, mac_s_gw, self.ip_dpi_table)

                    tunnel_to_ids = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == ids]
                    assert len(tunnel_to_ids) == 1
                    tunnel_to_ids = tunnel_to_ids[0]
                    self.controller.ip_src_dst_port_dscp_mod_src_dst_output(self.nodes['gw'], self.ip_ids_table, self.high_priority, ip_d, ip_s, proto, sport, dscp, ip_d_nat, ip_s_nat, tunnel_to_ids)
                    self.controller.ip_src_dst_port_mod_src_dst_macs_and_resubmit(self.nodes['gw'], self.ip_ids_table, self.high_priority, ip_d_nat, ip_s_nat, proto, sport, ip_d, ip_s, mac_d, mac_d_gw, self.ip_dpi_table)

                elif container_s['vm'] not in self.nodes.keys() and container_d['vm'] in self.nodes.keys():

                    # request

                    tunnel_to_ids = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == 'gw' and tunnel['remote'] == ids]
                    assert len(tunnel_to_ids) == 1
                    tunnel_to_ids = tunnel_to_ids[0]
                    self.controller.ip_src_dst_port_dscp_mod_src_dst_output(self.nodes['gw'], self.ip_ids_table, self.high_priority, ip_s, ip_d, proto, dport, dscp, ip_s_nat, ip_d_nat, tunnel_to_ids)
                    self.controller.ip_src_dst_port_mod_src_dst_macs_and_resubmit(self.nodes['gw'], self.ip_ids_table, self.high_priority, ip_s_nat, ip_d_nat, proto, dport, ip_s, ip_d, mac_s, mac_s_gw, self.ip_dpi_table)

                    # reply

                    tunnel_to_ids = [tunnel['ofport'] for tunnel in self.tunnels if tunnel['vm'] == container_d['vm'] and tunnel['remote'] == ids]
                    assert len(tunnel_to_ids) == 1
                    tunnel_to_ids = tunnel_to_ids[0]
                    self.controller.ip_src_dst_port_dscp_mod_src_dst_output(self.nodes[container_d['vm']], self.ip_ids_table, self.high_priority, ip_d, ip_s, proto, sport, dscp, ip_d_nat, ip_s_nat, tunnel_to_ids)
                    self.controller.ip_src_dst_port_mod_src_dst_macs_and_resubmit(self.nodes[container_d['vm']], self.ip_ids_table, self.high_priority, ip_d_nat, ip_s_nat, proto, sport, ip_d, ip_s, mac_d, mac_d_gw, self.ip_dpi_table)

    def _drop_action(self, source_list, destination_list, application, dscp, protocol='tcp'):

        for source in source_list:
            for destination in destination_list:
                container_s = [container for container in self.containers if container['ip'] == source]
                assert len(container_s) == 1
                container_s = container_s[0]
                container_d = [container for container in self.containers if container['ip'] == destination]
                assert len(container_d) == 1
                container_d = container_d[0]

                ip_s = container_s['ip']
                ip_d = container_d['ip']
                sport = [application, 'source']
                dport = [application, 'destination']
                proto = ip_ptoto(protocol)

                # ovs ip

                if container_s['vm'] in self.nodes.keys() and container_d['vm'] in self.nodes.keys():
                    self.controller.ip_src_dst_port_dscp_drop(self.nodes[container_s['vm']], self.ip_fw_table, self.high_priority, ip_s, ip_d, proto, dport, dscp)
                    self.controller.ip_src_dst_port_dscp_drop(self.nodes[container_d['vm']], self.ip_fw_table, self.high_priority, ip_d, ip_s, proto, sport, dscp)
                elif container_s['vm'] in self.nodes.keys() and container_d['vm'] not in self.nodes.keys():
                    self.controller.ip_src_dst_port_dscp_drop(self.nodes[container_s['vm']], self.ip_fw_table, self.high_priority, ip_s, ip_d, proto, dport, dscp)
                    self.controller.ip_src_dst_port_dscp_drop(self.nodes['gw'], self.ip_fw_table, self.high_priority, ip_d, ip_s, proto, sport, dscp)
                elif container_s['vm'] not in self.nodes.keys() and container_d['vm'] in self.nodes.keys():
                    self.controller.ip_src_dst_port_dscp_drop(self.nodes['gw'], self.ip_fw_table, self.high_priority, ip_s, ip_d, proto, dport, dscp)
                    self.controller.ip_src_dst_port_dscp_drop(self.nodes[container_d['vm']], self.ip_fw_table, self.high_priority, ip_d, ip_s, proto, sport, dscp)

    def _model_action(self, i, j, k):
        model_url = 'http://{0}:{1}/model'.format(self.ids_vms[i]['mgmt'], self.port)
        requests.post(model_url, json={'model': j})
        thr_url = 'http://{0}:{1}/threshold'.format(self.ids_vms[i]['mgmt'], self.port)
        requests.post(thr_url, json={'threshold': k})

    def _take_action(self, i):
        func, args = self._action_mapper(i)
        func(*args)

    def reset(self):
        ready = False
        while not ready:
            try:
                self._stop_traffic()
                self._clean_tables()
                self._start_traffic()
                tnow = time()
                if self.tstart is not None:
                    if tnow - self.tstart < self.tthreshold:
                        tsleep = self.tthreshold - (tnow - self.tstart)
                        print('Sleeping for {0} seconds'.format(tsleep))
                        sleep(tsleep)
                self._get_traffic()
                self._prepare_action_tensor()
                self.tstart = time()
                ready = True
            except Exception as e:
                print(e)
                sleep(1)
        return self.obs_traffic

    def step(self, action):
        self._take_action(action)
        self._get_traffic()
        eps = 1e-10
        normal = np.minimum(self.n_normal_out_avg, self.n_normal_in_avg) / (self.n_normal_in_avg + eps)
        attack = np.min([self.n_attack_out, self.n_attack_in], axis=0) / (self.n_attack_in + eps)
        reward = normal - np.sum(attack)
        done = False
        return self.obs_traffic, reward, done, {'r': reward, 'n': normal, 'a': attack}
