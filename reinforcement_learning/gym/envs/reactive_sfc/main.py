import json, os
import os.path as osp
import numpy as np

from reinforcement_learning.gym import spaces
from config import *
from time import sleep, time
from common.odl import Odl
from collections import deque
from common.ids import restart_ids
from common.utils import ip_proto
from threading import Thread
from itertools import cycle

from reinforcement_learning.gym.envs.reactive_sfc.init_and_reset import clean_ids_tables, clean_ovs_tables_via_api, init_ovs_tables, clean_ovs_tables_via_ssh, init_ids_tables
from reinforcement_learning.gym.envs.reactive_sfc.sdn_actions import forward_dscp_to_ids, unforward_dscp_from_ids, block_dscp, unblock_dscp
from reinforcement_learning.gym.envs.reactive_sfc.nfv_actions import set_vnf_param, reset_ids
from reinforcement_learning.gym.envs.reactive_sfc.sdn_state import get_flow_counts, reset_flow_collector, get_flag_counts, get_app_counts, get_ip_counts
from reinforcement_learning.gym.envs.reactive_sfc.nfv_state import get_intrusions, get_vnf_param
from reinforcement_learning.gym.envs.reactive_sfc.generate_traffic import set_seed, calculate_probs, prepare_traffic_on_interface, replay_traffic_on_interface

class ReactiveDiscreteEnv():

    def __init__(self, env_id, label, attack_data, aug, seed=None, policy=None):

        # id

        self.id = env_id

        # augment the data

        self.aug = aug

        # seed

        self.seed = seed

        # debug

        self.debug = False
        self.max_obs_time = 0

        # load logs

        with open(vms_fpath, 'r') as f:
            self.vms = json.load(f)

        with open(nodes_fpath, 'r') as f:
            self.nodes = json.load(f)

        with open(ofports_fpath, 'r') as f:
            self.ofports = json.load(f)

        # check ids model weights

        models = [item.split('.tflite')[0] for item in os.listdir(ids_model_weights_dir) if item.endswith('.tflite')]
        self.n_models = len(models)
        self.n_thrs = len(fpr_levels)

        # ovs vm

        ovs_vms = [vm for vm in self.vms if vm['role'] == 'ovs' and int(vm['vm'].split('_')[1]) == self.id]
        assert len(ovs_vms) == 1
        self.ovs_vm = ovs_vms[0]
        self.ovs_node = self.nodes[self.ovs_vm['vm']]
        set_seed(self.ovs_vm['mgmt'], flask_port, self.seed)

        # ids vms

        self.ids_vms = [vm for vm in self.vms if vm['role'] == 'ids' and int(vm['vm'].split('_')[1]) == self.id]
        self.n_ids = len(self.ids_vms)
        self.ids_nodes = [self.nodes[vm['vm']] for vm in self.ids_vms]
        for vm in self.ids_vms:
            restart_ids(vm)
        self.delay = [[] for _ in range(self.n_ids)]

        # controller

        controller_vm = [vm for vm in self.vms if vm['role'] == 'sdn']
        assert len(controller_vm) == 1
        self.controller_vm = controller_vm[0]
        self.controller = Odl(self.controller_vm['ip'])

        # tunnels and veth pairs

        self.internal_hosts = sorted([item for item in os.listdir(spl_dir) if osp.isdir(osp.join(spl_dir, item))])
        self.ovs_vxlans = [item for item in self.ofports if item['vm'] == self.ovs_vm['vm'] and item['type'] == 'vxlan']
        self.ovs_veths = [item for item in self.ofports if item['vm'] == self.ovs_vm['vm'] and item['type'] == 'veth']

        # ids tunnels

        self.ids_tunnels = []
        for ids_vm in self.ids_vms:
            tunnel_to_ids = [ofport['ofport'] for ofport in self.ofports if ofport['type'] == 'vxlan' and ofport['vm'] == self.ovs_vm['vm'] and ofport['remote'] == ids_vm['vm']]
            assert len(tunnel_to_ids) == 1
            tunnel_to_ids = tunnel_to_ids[0]
            self.ids_tunnels.append(tunnel_to_ids)

        # configure ids

        for ids_vm, ids_node in zip(self.ids_vms, self.ids_nodes):
            ids_vxlan = [item for item in self.ofports if item['type'] == 'vxlan' and item['vm'] == ids_vm['vm']]
            assert len(ids_vxlan) == 1
            ids_vxlan = ids_vxlan[0]
            ids_veths = [item for item in self.ofports if item['type'] == 'veth' and item['vm'] == ids_vm['vm']]
            clean_ids_tables(self.controller, ids_node)
            init_ids_tables(self.controller, ids_node, ids_vxlan, ids_veths)
            idx = int(ids_vm['vm'].split('_')[2])
            set_vnf_param(ids_vm['ip'], flask_port, 'dscp', idx)

        # time

        self.tstart = None
        self.tstep = None
        self.step_duration = episode_duration / nsteps

        # traffic

        if type(label) is not list:
            label = [label]
        for l in label:
            assert l in attack_data.keys(), f'No data found for attack {l}!'
        self.profiles = calculate_probs(stats_dir, [0, *label])
        self.label = cycle(label)
        self.attack_data = attack_data

        # obs

        self.stack_size = obs_stack_size
        self.n_apps = len(applications)
        self.n_flags = len(tcp_flags)
        self.n_dscps = 2 ** self.n_ids

        self.sdn_on_off_frame_shape = (self.n_dscps, self.n_ids + 1)
        self.sdn_on_off_frame = np.zeros(self.sdn_on_off_frame_shape)

        self.nfv_on_off_frame_shape = (self.n_ids, self.n_models + self.n_thrs)
        self.nfv_on_off_frame = np.zeros(self.nfv_on_off_frame_shape)
        self.nfv_on_off_frame[:, 0] = 1  # default model idx is 0
        self.nfv_on_off_frame[:, self.n_models] = 1  # default thr idx is 0

        obs_shape = (self.stack_size, self.n_apps * 2 +
                     (self.n_flags + 1) * 2 +
                     self.n_apps * self.n_ids +
                     np.prod(self.sdn_on_off_frame_shape) +
                     np.prod(self.nfv_on_off_frame_shape))

        self.samples_by_app = np.zeros((self.n_apps, 2))
        self.samples_by_flag = np.zeros((self.n_flags + 1, 2))
        self.app_counts_stack = deque(maxlen=self.stack_size)

        self.in_samples_by_attacker_stack = deque(maxlen=self.stack_size)
        self.out_samples_by_attacker_stack = deque(maxlen=self.stack_size)

        self.intrusion_ips = [[[] for _ in range(self.n_apps)] for __ in range(self.n_ids)]
        self.ips_to_check_or_block = [[[] for _ in range(self.n_apps)] for __ in range(self.n_ids + 1)]
        self.intrusion_numbers = [[[] for _ in range(self.n_apps)] for __ in range(self.n_ids)]

        # actions

        self.n_forward_actions = self.n_dscps * self.n_ids
        self.n_unforward_actions = self.n_dscps * self.n_ids
        self.n_block_actions = self.n_dscps
        self.n_unblock_actions = self.n_dscps
        self.n_ids_actions = (self.n_models + self.n_thrs) * self.n_ids

        #act_dim = self.n_forward_actions + self.n_unforward_actions + self.n_block_actions + self.n_unblock_actions + self.n_ids_actions + 1
        act_dim = self.n_forward_actions + self.n_block_actions + self.n_ids_actions + 1

        self.actions_queue = deque()

        # start acting

        actor = Thread(target=self._act, daemon=True)
        actor.start()

        # log actions

        with open(actions_fpath, 'w') as f:
            for i in range(act_dim):
                fun, args, idx_val, q = self._action_mapper(i)
                line = f"{i};{fun.__name__};{idx_val};{','.join([str(item) for item in args])}\n"
                f.write(line)

        # default policy

        if policy is not None:
            self.default_reset_actions = policy['reset']
            self.default_step_actions = policy['step']
        else:
            self.default_reset_actions = None
            self.default_step_actions = None

        # reward

        self.n_attackers = len(attackers)
        self.samples_by_attacker = np.zeros((self.n_attackers + 1, 2))

        # spaces

        self.observation_space = spaces.Box(low=0, high=np.inf, shape=obs_shape, dtype=np.float32)
        self.action_space = spaces.Discrete(act_dim)

        print('Observation shape: {0}'.format(obs_shape))
        print('Number of actions: {0}'.format(act_dim))

        self.in_samples = 0
        self.out_samples = 0

    def _act(self):
        while True:
            if len(self.actions_queue) > 0:
                func, args = self.actions_queue.pop()
                func(*args)

    def _process_app_samples(self, samples):
        x = np.zeros((self.n_apps, 3))
        flow_ids = [[] for _ in applications]
        for id, features, flags in samples:
            if id is not None:
                src_port = id[1]
                dst_port = id[3]
                idx = None
                if id[4] in [1, 6, 17]:
                    proto, proto_number = ip_proto(id[4])
                    if (proto, src_port) in applications:
                        idx = applications.index((proto, src_port))
                    elif (proto, dst_port) in applications:
                        idx = applications.index((proto, dst_port))
                    elif (proto,) in applications:
                        idx = applications.index((proto,))
                    if idx is not None:
                        if id not in flow_ids[idx]:
                            flow_ids[idx].append(id)
                            x[idx, 0] += 1
                        x[idx, 1] += 1
                        x[idx, 2] += features[0]
        return x

    def _process_reward_samples(self, in_samples, out_ids):
        x = np.zeros((self.n_attackers + 1, 2))
        for id, features, flags in in_samples:
            if id is not None:
                src_ip = id[0]
                dst_ip = id[2]
                if src_ip in attackers:
                    idx = attackers.index(src_ip)
                    x[idx] += 1
                elif dst_ip in attackers:
                    idx = attackers.index(dst_ip)
                    x[idx] += 1
                else:
                    idx = -1
                x[idx, 0] += 1
                if id in out_ids:
                    x[idx, 1] += 1
        return x

    def _measure_delay(self):
        for i in range(self.n_ids):
            self.delay[i].append(get_vnf_param(self.ids_vms[i]['ip'], flask_port, 'delay'))

    def _update_intrusions(self):

        intrusion_ips = [[[] for _ in range(self.n_apps)] for __ in range(self.n_ids)]
        intrusion_numbers = [[[] for _ in range(self.n_apps)] for __ in range(self.n_ids)]

        for i in range(self.n_ids):
            intrusions = get_intrusions(self.ids_vms[i]['ip'], flask_port)
            for intrusion in intrusions:
                src_ip = intrusion[0]
                src_port = intrusion[1]
                dst_ip = intrusion[2]
                dst_port = intrusion[3]
                if intrusion[4] in [1, 6, 17]:
                    proto, proto_number = ip_proto(intrusion[4])
                    if (proto, src_port) in applications:
                        app_idx = applications.index([proto, src_port])
                    elif (proto, dst_port) in applications:
                        app_idx = applications.index([proto, dst_port])
                    else:
                        app_idx = applications.index([proto])

                    # update recent intrusions

                    if src_ip not in intrusion_ips[i][app_idx] and src_ip not in self.internal_hosts:
                        intrusion_ips[i][app_idx].append(src_ip)
                        intrusion_numbers[i][app_idx].append(1)
                    elif src_ip in intrusion_ips[i][app_idx] and src_ip not in self.internal_hosts:
                        idx = intrusion_ips[i][app_idx].index(src_ip)
                        intrusion_numbers[i][app_idx][idx] += 1
                    if dst_ip not in intrusion_ips[i][app_idx] and dst_ip not in self.internal_hosts:
                        intrusion_ips[i][app_idx].append(dst_ip)
                        intrusion_numbers[i][app_idx].append(1)
                    elif dst_ip in intrusion_ips[i][app_idx] and dst_ip not in self.internal_hosts:
                        idx = intrusion_ips[i][app_idx].index(dst_ip)
                        intrusion_numbers[i][app_idx][idx] += 1

                    # update all intrusions

                    if src_ip not in self.intrusion_ips[i][app_idx] and src_ip not in self.internal_hosts:
                        self.intrusion_ips[i][app_idx].append(src_ip)
                        self.intrusion_numbers[i][app_idx].append(1)
                    elif src_ip in self.intrusion_ips[i][app_idx] and src_ip not in self.internal_hosts:
                        idx = self.intrusion_ips[i][app_idx].index(src_ip)
                        self.intrusion_numbers[i][app_idx][idx] += 1
                    if dst_ip not in self.intrusion_ips[i][app_idx] and dst_ip not in self.internal_hosts:
                        self.intrusion_ips[i][app_idx].append(dst_ip)
                        self.intrusion_numbers[i][app_idx].append(1)
                    elif dst_ip in self.intrusion_ips[i][app_idx] and dst_ip not in self.internal_hosts:
                        idx = self.intrusion_ips[i][app_idx].index(dst_ip)
                        self.intrusion_numbers[i][app_idx][idx] += 1

        return intrusion_ips, intrusion_numbers

    def _get_precision(self, intrusion_ips, intrusion_numbers):
        tp = 0
        fp = 0
        for intrusion_ips_by_ids, intrusion_numbers_by_ids in zip(intrusion_ips, intrusion_numbers):
            for intrusion_ips_by_app_and_ids, intrusion_numbers_by_app_and_ids in zip(intrusion_ips_by_ids, intrusion_numbers_by_ids):
                for ip, n in zip(intrusion_ips_by_app_and_ids, intrusion_numbers_by_app_and_ids):
                    #print(ip, n)
                    if ip in attackers:
                        tp += n
                    else:
                        fp += n
        if (tp + fp) > 0:
            precision = tp / (tp + fp)
        else:
            precision = np.nan
        #self.precision.append(precision)
        return precision

    def _get_normal_attack(self, sample_counts):

        reward = 0
        normal = []
        attack = []

        for i in range(self.n_attackers + 1):
            b = sample_counts[i, 0]  # before
            a = sample_counts[i, 1]  # after
            if b > 0:
                blocked = np.clip(b - a, 0, b)
                allowed = np.clip(a, 0, b)
                allowed = np.clip(a, 0, b)
                if i < self.n_attackers:
                    attack.append(blocked / b)
                elif i == self.n_attackers:
                    normal.append(allowed / b)

        if len(normal) > 0:
            normal = np.mean(normal)
            reward += normal
        else:
            normal = np.nan
            reward += 1

        if len(attack) > 0:
            attack = np.mean(attack)
            reward += attack
        else:
            attack = np.nan
            reward += 0

        return normal, attack

    def _action_mapper_long(self, i):

        if i < self.n_forward_actions:
            action_array = np.zeros(self.n_forward_actions)
            action_array[i] = 1
            action_array = action_array.reshape(self.n_dscps, self.n_ids)
            dscp_i, ids_i = np.where(action_array == 1)
            dscp_idx = dscp_i[0]
            ids_idx = ids_i[0]
            dscp = dscp_idx
            action_fun = forward_dscp_to_ids
            args = (self.controller, self.ovs_node, ids_tables[ids_idx], priorities['lower'], dscp, self.ids_tunnels[ids_idx])
            on_off_idx_and_value = (dscp_idx, ids_idx, 1)
            queue_the_action = True
        elif i < self.n_forward_actions + self.n_unforward_actions:
            action_array = np.zeros(self.n_unforward_actions)
            action_array[i - self.n_forward_actions] = 1
            action_array = action_array.reshape(self.n_dscps, self.n_ids)
            dscp_i, ids_i = np.where(action_array == 1)
            dscp_idx = dscp_i[0]
            ids_idx = ids_i[0]
            dscp = dscp_idx
            action_fun = unforward_dscp_from_ids
            args = (self.controller, self.ovs_node, ids_tables[ids_idx], dscp)
            on_off_idx_and_value = (dscp_idx, ids_idx, 0)
            queue_the_action = True
        elif i < self.n_forward_actions + self.n_unforward_actions + self.n_block_actions:
            action_array = np.zeros(self.n_block_actions)
            action_array[i - self.n_forward_actions - self.n_unforward_actions] = 1
            dscp = np.where(action_array == 1)[0][0]
            action_fun = block_dscp
            args = (self.controller, self.ovs_node, block_table, priorities['higher'], dscp)
            on_off_idx_and_value = (dscp, self.n_ids, 1)
            queue_the_action = True
        elif i < self.n_forward_actions + self.n_unforward_actions + self.n_block_actions + self.n_unblock_actions:
            action_array = np.zeros(self.n_unblock_actions)
            action_array[i - self.n_forward_actions - self.n_unforward_actions - self.n_block_actions] = 1
            dscp = np.where(action_array == 1)[0][0]
            action_fun = unblock_dscp
            args = (self.controller, self.ovs_node, block_table, dscp)
            on_off_idx_and_value = (dscp, self.n_ids, 0)
            queue_the_action = True
        elif i < self.n_forward_actions + self.n_unforward_actions + self.n_block_actions + self.n_unblock_actions + self.n_ids_actions:
            action_array = np.zeros(self.n_ids_actions)
            action_array[i - self.n_forward_actions - self.n_unforward_actions - self.n_block_actions - self.n_unblock_actions] = 1
            action_array = action_array.reshape(self.n_ids, self.n_models + self.n_thrs)
            ids_i, value_i = np.where(action_array == 1)
            ids_idx = ids_i[0]
            value = value_i[0]
            ids_ip = self.ids_vms[ids_idx]['ip']
            on_off_value = np.array(self.nfv_on_off_frame[ids_idx, :])
            if value < self.n_models:
                param = 'model'
                value = int(value)
                on_off_value[:self.n_models] = 0
                on_off_value[value] = 1
            else:
                param = 'threshold'
                value = int(value) - self.n_models
                on_off_value[self.n_models:] = 0
                on_off_value[value] = 1
            action_fun = set_vnf_param
            args = (ids_ip, flask_port, param, value)
            on_off_idx_and_value = (ids_idx, on_off_value)
            queue_the_action = False
        else:
            action_fun = lambda *args: None
            args = ()
            on_off_idx_and_value = None
            queue_the_action = False
        return action_fun, args, on_off_idx_and_value, queue_the_action

    def _action_mapper(self, i):

        if i < self.n_forward_actions:
            action_array = np.zeros(self.n_forward_actions)
            action_array[i] = 1
            action_array = action_array.reshape(self.n_dscps, self.n_ids)
            dscp_i, ids_i = np.where(action_array == 1)
            dscp_idx = dscp_i[0]
            ids_idx = ids_i[0]
            dscp = dscp_idx
            if self.sdn_on_off_frame[dscp_idx, ids_idx] == 0:
                action_fun = forward_dscp_to_ids
                args = (self.controller, self.ovs_node, ids_tables[ids_idx], priorities['lower'], dscp, self.ids_tunnels[ids_idx])
                on_off_idx_and_value = (dscp_idx, ids_idx, 1)
            else:
                action_fun = unforward_dscp_from_ids
                args = (self.controller, self.ovs_node, ids_tables[ids_idx], dscp)
                on_off_idx_and_value = (dscp_idx, ids_idx, 0)
            queue_the_action = True
        elif i < self.n_forward_actions + self.n_block_actions:
            action_array = np.zeros(self.n_block_actions)
            action_array[i - self.n_forward_actions] = 1
            dscp = np.where(action_array == 1)[0][0]
            if self.sdn_on_off_frame[dscp, self.n_ids] == 0:
                action_fun = block_dscp
                args = (self.controller, self.ovs_node, block_table, priorities['higher'], dscp)
                on_off_idx_and_value = (dscp, self.n_ids, 1)
            else:
                action_fun = unblock_dscp
                args = (self.controller, self.ovs_node, block_table, dscp)
                on_off_idx_and_value = (dscp, self.n_ids, 0)
            queue_the_action = True
        elif i < self.n_forward_actions + self.n_block_actions + self.n_ids_actions:
            action_array = np.zeros(self.n_ids_actions)
            action_array[i - self.n_forward_actions - self.n_block_actions] = 1
            action_array = action_array.reshape(self.n_ids, self.n_models + self.n_thrs)
            ids_i, value_i = np.where(action_array == 1)
            ids_idx = ids_i[0]
            value = value_i[0]
            ids_ip = self.ids_vms[ids_idx]['ip']
            on_off_value = np.array(self.nfv_on_off_frame[ids_idx, :])
            if value < self.n_models:
                param = 'model'
                value = int(value)
                on_off_value[:self.n_models] = 0
                on_off_value[value] = 1
            else:
                param = 'threshold'
                on_off_value[self.n_models:] = 0
                on_off_value[value] = 1
                value = int(value) - self.n_models
            action_fun = set_vnf_param
            args = (ids_ip, flask_port, param, value)
            on_off_idx_and_value = (ids_idx, on_off_value)
            queue_the_action = False
        else:
            action_fun = lambda *args: None
            args = ()
            on_off_idx_and_value = None
            queue_the_action = False
        return action_fun, args, on_off_idx_and_value, queue_the_action

    def _take_action(self, i):
        func, args, on_off_idx_and_value, queue_the_action = self._action_mapper(i)
        if queue_the_action:
            self.actions_queue.appendleft((func, args))
        else:
            func(*args)
        if self.debug:
            print(func, args, on_off_idx_and_value)
        if on_off_idx_and_value is not None:
            if len(on_off_idx_and_value) == 3:
                i, j, val = on_off_idx_and_value
                self.sdn_on_off_frame[i, j] = val
            elif len(on_off_idx_and_value) == 2:
                i, val = on_off_idx_and_value
                self.nfv_on_off_frame[i, :] = val

    def _rearange_counts(self, flows, counts, flows_r):
        counts_r = np.zeros_like(counts)
        for i in range(len(flows_r)):
            if flows_r[i] in flows:
                idx = flows.index(flows_r[i])
                counts_r[i] = counts[idx]
        return counts_r

    def reset(self, sleep_duration=5):

        attack_label = next(self.label)
        attack_ips, attack_directions = self.attack_data[attack_label]

        #print('Reset start in', self.id)

        if self.debug:
            print(f'Max obs time in {self.id}: {self.max_obs_time}')

        # end of the episode

        tnow = time()
        if self.tstart is not None:
            print('Episode duration: {0}'.format(tnow - self.tstart))

        # step count

        self.step_count = 0

        # reset flow collector

        reset_flow_collector(self.ovs_vm['mgmt'], flask_port)

        # clear lists

        self.precision = []

        # reset ids

        for i in range(self.n_ids):
            reset_ids(self.ids_vms[i]['mgmt'], flask_port)
        self.intrusion_ips = [[[] for _ in range(self.n_apps)] for __ in range(self.n_ids)]
        self.intrusion_numbers = [[[] for _ in range(self.n_apps)] for __ in range(self.n_ids)]
        self.delay = [[] for _ in range(self.n_ids)]
        self.ips_to_check_or_block = [[[] for _ in range(self.n_apps)] for __ in range(self.n_ids + 1)]

        sdn_restart_required = False

        # clean tables and wait for sdn configuration to be processed

        tables = np.arange(in_table, out_table)
        ready = False
        attempt = 0
        attempt_max = 5
        while not ready:
            clean_ovs_tables_via_api(self.controller, self.ovs_node)
            sleep(sleep_duration)
            count = 0
            for table in tables:
                flows, counts = get_flow_counts(self.controller, self.ovs_node, table)
                if len(flows) == 0:
                    count += 1
                else:
                    print(f'Problem with table {table}: {len(flows)} flow(s) found')
                    attempt += 1
                    if attempt >= attempt_max:
                        sdn_restart_required = True
                    break
            if count == len(tables):
                ready = True
            if sdn_restart_required:
                break

        if not sdn_restart_required:
            print('Flow tables are cleared in env', self.id)

        # fill tables and wait for sdn configuration to be processed

        if not sdn_restart_required:
            ready = False
            attempt = 0
            while not ready:
                init_ovs_tables(self.controller, self.ovs_node, self.ovs_vxlans, self.ovs_veths, attack_ips, attack_directions)
                sleep(sleep_duration)
                count = 0
                for table in tables:
                    if table == in_table:
                        n_flows_required = self.n_ids + 1
                    elif table == app_table:
                        n_flows_required = (len(applications) - 2) * 2 + 2
                    elif table == flag_table:
                        n_flows_required = self.n_flags + 1
                    elif table in [attacker_in_table, attacker_out_table]:
                        n_flows_required = len(attack_ips) * len(attack_directions) + 1
                    else:
                        n_flows_required = 1
                    flows, counts = get_flow_counts(self.controller, self.ovs_node, table)
                    if len(flows) == n_flows_required:
                        count += 1
                    else:
                        print(f'Problem with table {table}: {n_flows_required} required, but {len(flows)} flow(s) found')
                        attempt += 1
                        if attempt >= attempt_max:
                            sdn_restart_required = True
                        clean_ovs_tables_via_ssh(self.ovs_vm)
                        break
                if count == len(tables):
                    ready = True
                if sdn_restart_required:
                    break

        print('sdn restart required:', sdn_restart_required)

        if not sdn_restart_required:

            # set time

            if self.tstart is not None:
                tnow = time()
                if (tnow - self.tstart) < episode_duration:
                    sleep(episode_duration - (tnow - self.tstart))

            # default reset actions

            if self.default_reset_actions is not None:
                for action in self.default_reset_actions:
                    self._take_action(action)

            self.tstart = time()
            self.tstep = time()

            # calculate obs

            self.app_counts_stack.clear()
            self.samples_by_app = np.zeros((self.n_apps, 2))
            self.samples_by_flag = np.zeros((self.n_flags + 1, 2))
            self.samples_by_attacker = np.zeros((self.n_attackers + 1, 2))

            self.sdn_on_off_frame = np.zeros(self.sdn_on_off_frame_shape)
            self.nfv_on_off_frame = np.zeros(self.nfv_on_off_frame_shape)
            self.nfv_on_off_frame[:, 0] = 1  # default model idx is 0
            self.nfv_on_off_frame[:, self.n_models] = 1  # default thr idx is 0

            while len(self.app_counts_stack) < self.app_counts_stack.maxlen:

                app_samples = get_app_counts(self.ovs_vm['ip'], flask_port, app_table)
                samples_by_app = np.zeros((self.n_apps, 2))
                for app in applications:
                    if app in app_samples['applications']:
                        idx = app_samples['applications'].index(app)
                        samples_by_app[idx, 0] = app_samples['packets'][idx]
                        samples_by_app[idx, 1] = app_samples['bytes'][idx]

                flag_samples = get_flag_counts(self.ovs_vm['ip'], flask_port, flag_table)
                samples_by_flag = np.zeros((self.n_flags + 1, 2))
                for flag in tcp_flags:
                    if flag in flag_samples['flags']:
                        idx = flag_samples['flags'].index(flag)
                    else:
                        idx = -1
                    samples_by_flag[idx, 0] = flag_samples['packets'][idx]
                    samples_by_flag[idx, 1] = flag_samples['bytes'][idx]

                frame = np.hstack([
                    ((samples_by_app - self.samples_by_app) / (np.sum(samples_by_app, axis=0) + 1e-10)).reshape(1, -1).flatten(),  # apps
                    ((samples_by_flag - self.samples_by_flag) / (np.sum(samples_by_flag, axis=0) + 1e-10)).reshape(1, -1).flatten(),  # flags
                    np.zeros(self.n_apps * self.n_ids),  # intrusions
                    np.array(self.sdn_on_off_frame).reshape(1, -1).flatten(),  # sdn actions
                    np.array(self.nfv_on_off_frame). reshape(1, -1).flatten()  # nfv actions
                ])
                self.app_counts_stack.append(frame)
                self.samples_by_app = np.array(samples_by_app)
                self.samples_by_flag = np.array(samples_by_flag)

            obs = np.array(self.app_counts_stack)

            # generate traffic

            for host in self.internal_hosts:

                if host in self.profiles[attack_label].keys():
                    prob_idx = attack_label
                    if self.aug:
                        aug = {'ips': attack_ips, 'directions': attack_directions}
                    else:
                        aug = None
                elif host in self.profiles[0].keys():
                    prob_idx = 0
                    aug = None
                else:
                    prob_idx = -1

                if prob_idx >= 0:
                    fname_idx = np.random.choice(np.arange(len(self.profiles[prob_idx][host][1])), p=self.profiles[prob_idx][host][1])
                    fnames = [f'{self.profiles[prob_idx][host][0][fname_idx]}_label:{prob_idx}']
                    augments = [aug]
                    if prob_idx > 0:
                        fnames.append(f'{self.profiles[prob_idx][host][0][fname_idx]}_label:{0}')
                        augments.append(None)
                    for fname, aug in zip(fnames, augments):
                        flows = prepare_traffic_on_interface(self.ovs_vm['mgmt'], flask_port, host, fname, augment=aug)
                        if self.debug:
                            print(prob_idx, fname, len(flows))

                replay_traffic_on_interface(self.ovs_vm['mgmt'], flask_port, episode_duration)

            print('Reset complete in env', self.id)

        else:

            obs = None

        return obs

    def step(self, action):

        # step count

        self.step_count += 1
        if self.debug:
            print(self.step_count, action)

        if len(self.actions_queue) > 0:
            print('There is still an action in the queue, consider decreasing action frequency!')

        # take an action and measure time

        t0 = time()
        if self.default_step_actions is not None:
            for action in self.default_step_actions:
                self._take_action(action)
        else:
            self._take_action(action)
        if self.debug:
            print('take action', time() - t0)
        tnow = time()
        if (tnow - self.tstart) < self.step_duration * self.step_count:
            sleep(self.step_duration * self.step_count - (tnow - self.tstart))
            if self.debug:
                print(f'Sleeping for {self.step_duration - (tnow - self.tstep)} seconds')
        self.tstep = time()

        # obs

        t0 = time()

        app_samples = get_app_counts(self.ovs_vm['ip'], flask_port, app_table)
        flag_samples = get_flag_counts(self.ovs_vm['ip'], flask_port, flag_table)

        if time() - t0 > self.max_obs_time:
            self.max_obs_time = time() - t0

        # building obs frame

        processed_counts = []

        samples_by_app = np.zeros((self.n_apps, 2))
        for app in applications:
            if app in app_samples['applications']:
                idx = app_samples['applications'].index(app)
                samples_by_app[idx, 0] = app_samples['packets'][idx]
                samples_by_app[idx, 1] = app_samples['bytes'][idx]
        processed_counts.append(((samples_by_app - self.samples_by_app) / (np.sum(samples_by_app, axis=0) + 1e-10)).reshape(1, -1).flatten())

        self.samples_by_flag = np.zeros((self.n_flags + 1, 2))
        flag_samples = get_flag_counts(self.ovs_vm['ip'], flask_port, flag_table)
        samples_by_flag = np.zeros((self.n_flags + 1, 2))
        for flag in tcp_flags:
            if flag in flag_samples['flags']:
                idx = flag_samples['flags'].index(flag)
            else:
                idx = -1
            samples_by_flag[idx, 0] = flag_samples['packets'][idx]
            samples_by_flag[idx, 1] = flag_samples['bytes'][idx]
        processed_counts.append(((samples_by_flag - self.samples_by_flag) / (np.sum(samples_by_flag, axis=0) + 1e-10)).reshape(1, -1).flatten())

        nintrusions = np.zeros((self.n_apps, self.n_ids))
        for i in range(self.n_apps):
            for j in range(self.n_ids):
                nintrusions[i, j] = np.sum(self.intrusion_numbers[j][i])
        processed_counts.append(nintrusions.reshape(1, -1).flatten())

        processed_counts.append(np.array(self.sdn_on_off_frame).reshape(1, -1).flatten())
        processed_counts.append(np.array(self.nfv_on_off_frame).reshape(1, -1).flatten())

        frame = np.hstack(processed_counts)
        self.samples_by_app = np.array(samples_by_app)
        self.app_counts_stack.append(frame)
        obs = np.array(self.app_counts_stack)

        # intrusions

        intrusion_ips, intrusion_numbers = self._update_intrusions()
        self._measure_delay()
        if self.debug:
            print(f'Delays: {[np.mean(item) for item in self.delay]}')

        # append precision

        precision = self._get_precision(intrusion_ips, intrusion_numbers)

        # reward and info

        in_samples = get_ip_counts(self.ovs_vm['ip'], flask_port, attacker_in_table)
        out_samples = get_ip_counts(self.ovs_vm['ip'], flask_port, attacker_out_table)
        samples_by_attacker = np.zeros((self.n_attackers + 1, 2))
        for ip, npkts in zip(in_samples['ips'], in_samples['packets']):
            if ip in attackers:
                idx = attackers.index(ip)
            else:
                idx = -1
            samples_by_attacker[idx, 0] += npkts
        for ip, npkts in zip(out_samples['ips'], out_samples['packets']):
            if ip in attackers:
                idx = attackers.index(ip)
            else:
                idx = -1
            samples_by_attacker[idx, 1] += npkts
        normal, attack = self._get_normal_attack(samples_by_attacker - self.samples_by_attacker)
        self.samples_by_attacker = np.array(samples_by_attacker)
        reward = self._calculate_reward(normal, attack, precision)
        info = {'n': normal, 'a': attack, 'p': precision}
        done = False

        return obs, reward, done, info

    def _calculate_reward(self, normal, attack, precision):
        reward = reward_min
        if np.isnan(normal):
            reward += 1
        else:
            reward += normal
        if np.isnan(attack):
            reward += 0
        else:
            reward += attack
        if np.isnan(precision):
            reward += precision_weight * 0.5
        else:
            reward += precision_weight * precision
        return reward

    def reward(self, n_steps_backward=0, n_steps_forward=0):

        # lists

        rewards = []
        infos = []

        # get report

        t_start = time()

        in_pkts, out_pkts, state_timestamps = get_flow_report(self.ovs_vm['ip'], flask_port)
        print(f'In environment {self.id}, packets in: {len(in_pkts)}, packets out: {len(out_pkts)}')
        in_pkts_timestamps = np.array([item[0] for item in in_pkts])
        out_pkts_timestamps = np.array([item[0] for item in out_pkts])
        print(f'Time spent to get report: {time() - t_start}')

        # calculate reward

        ts_last = 0
        for ts_i, ts_now in enumerate(state_timestamps[self.stack_size:]):
            t_ = time()
            in_idx = np.where((in_pkts_timestamps > ts_last) & (in_pkts_timestamps <= ts_now))[0]
            print(ts_last, ts_now, len(in_idx))
            in_samples = [in_pkts[i][1:] for i in in_idx]
            out_idx = np.where((out_pkts_timestamps > (ts_last - n_steps_backward * self.step_duration)) & (out_pkts_timestamps <= (ts_now + n_steps_forward * self.step_duration)))[0]
            out_sample_ids = [out_pkts[i][1] for i in out_idx]
            ts_last = ts_now
            samples_by_attacker = self._process_reward_samples(in_samples, out_sample_ids)
            normal, attack = self._get_normal_attack(samples_by_attacker)
            precision = self.precision[ts_i]
            reward = self._calculate_reward(normal, attack, precision)
            rewards.append(reward)
            infos.append({'r': reward, 'n': normal, 'a': attack, 'p': precision})
            print(f'Time spent to calculate reward at {ts_i}: {time() - t_}, in: {len(in_samples)}, out: {len(out_sample_ids)}')

        return rewards, infos
