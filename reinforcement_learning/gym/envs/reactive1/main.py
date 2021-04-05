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

from reinforcement_learning.gym.envs.reactive1.init_flow_tables import clean_ids_tables, init_ovs_tables
from reinforcement_learning.gym.envs.reactive1.sdn_actions import mirror_app_to_ids, unmirror_app_from_ids, mirror_ip_app_to_ids, unmirror_ip_app_from_ids, block_ip_app, unblock_ip_app
from reinforcement_learning.gym.envs.reactive1.nfv_actions import set_vnf_param, reset_ids
from reinforcement_learning.gym.envs.reactive1.sdn_state import get_flow_counts, get_flow_samples
from reinforcement_learning.gym.envs.reactive1.nfv_state import get_intrusions
from reinforcement_learning.gym.envs.reactive1.generate_traffic import set_seed, generate_ip_traffic_on_interface

class AttackMitigationEnv():

    def __init__(self, env_id, label, seed=None, policy=None):

        # id

        self.id = env_id

        # seed

        self.seed = seed

        # debug

        self.debug = True

        # load logs

        with open(vms_fpath, 'r') as f:
            self.vms = json.load(f)

        with open(nodes_fpath, 'r') as f:
            self.nodes = json.load(f)

        with open(ofports_fpath, 'r') as f:
            self.ofports = json.load(f)

        # check ids model weights

        ids_model_names = [item.split('.tflite')[0] for item in os.listdir(ids_model_weights_dir) if item.endswith('.tflite')]
        spl = [item.split('_') for item in ids_model_names]
        steps = sorted(list(set([item[0] for item in spl])))
        models = sorted(list(set([item[1] for item in spl])))
        self.n_steps = len(steps)
        self.n_models = len(models)

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
        assert (self.n_ids + 2) <= out_table
        for vm in self.ids_vms:
            restart_ids(vm)

        # controller

        controller_vm = [vm for vm in self.vms if vm['role'] == 'sdn']
        assert len(controller_vm) == 1
        controller_name = controller_vm[0]['vm']
        controller_ip = controller_vm[0]['ip']
        if controller_name == ctrl_name:
            self.controller = Odl(controller_ip)

        # tables and tunnels

        self.internal_hosts = sorted([item.split(csv_postfix)[0] for item in os.listdir(spl_dir) if osp.isfile(osp.join(spl_dir, item)) and item.endswith(csv_postfix)])
        clean_ids_tables(self.controller, self.ids_nodes)
        self.tunnels = [item for item in self.ofports if item['type'] == 'vxlan']
        self.veths = [item for item in self.ofports if item['type'] == 'veth']

        # time

        self.tstart = None
        self.tstep = None
        self.step_duration = episode_duration / nsteps

        # traffic

        self.label = label

        # obs

        self.stack_size = obs_stack_size
        self.n_apps = len(applications)
        on_off_frame_shape = (self.n_apps, (self.n_ids + 1) * self.n_ids)
        self.on_off_frame = np.zeros(on_off_frame_shape)
        obs_shape = (self.stack_size, self.n_apps, 4 + self.n_ids + on_off_frame_shape[1])
        self.app_counts_stack = deque(maxlen=self.stack_size)
        self.in_samples_by_attacker_stack = deque(maxlen=self.stack_size)
        self.out_samples_by_attacker_stack = deque(maxlen=self.stack_size)
        self.intrusion_ips = [[[] for _ in range(self.n_apps)] for __ in range(self.n_ids)]
        self.intrusion_numbers = [[[] for _ in range(self.n_apps)] for __ in range(self.n_ids)]

        # actions

        self.n_mirror_app_actions = self.n_apps * self.n_ids
        self.n_unmirror_app_actions = self.n_apps * self.n_ids
        self.n_mirror_int_actions = self.n_apps * (self.n_ids - 1) * self.n_ids
        self.n_unmirror_int_actions = self.n_apps * (self.n_ids - 1) * self.n_ids
        self.n_block_actions = self.n_apps * self.n_ids
        self.n_unblock_actions = self.n_apps * self.n_ids
        self.n_ids_actions = (self.n_models + self.n_steps) * self.n_ids
        act_dim = self.n_mirror_app_actions + self.n_unmirror_app_actions + self.n_mirror_int_actions + self.n_unmirror_int_actions + \
                  self.n_block_actions + self.n_unblock_actions + self.n_ids_actions + 1

        # log actions

        with open(actions_fpath, 'w') as f:
            for i in range(act_dim):
                fun, args, idx_val = self._action_mapper(i)
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

        # spaces

        self.observation_space = spaces.Box(low=0, high=np.inf, shape=obs_shape, dtype=np.float32)
        self.action_space = spaces.Discrete(act_dim)

        print('Observation shape: {0}'.format(obs_shape))
        print('Number of actions: {0}'.format(act_dim))

        self.in_samples = 0
        self.out_samples = 0

    def _process_app_samples(self, samples):
        x = np.zeros((self.n_apps, 2))
        for id, features, flags in samples:
            src_port = id[1]
            dst_port = id[3]
            if id[4] in [1, 6, 17]:
                proto, proto_number = ip_proto(id[4])
                if (proto, src_port) in applications:
                    idx = applications.index((proto, src_port))
                    x[idx, 0] += features[0]
                elif (proto, dst_port) in applications:
                    idx = applications.index((proto, dst_port))
                    x[idx, 0] += features[0]
                elif (proto, ) in applications:
                    idx = applications.index((proto, ))
                    x[idx, 0] += features[0]
        return x

    def _process_reward_samples(self, samples):
        x = np.zeros((self.n_attackers + 1, 1))
        for id, features, flags in samples:
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
                x[idx] += 1
        return x

    def _update_intrusions(self):
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
                        app_idx = applications.index((proto, src_port))
                    elif (proto, dst_port) in applications:
                        app_idx = applications.index((proto, dst_port))
                    else:
                        app_idx = applications.index((proto,))
                    if src_ip not in self.intrusion_ips[i][app_idx] and src_ip not in self.internal_hosts:
                        self.intrusion_ips[i][app_idx].append(src_ip)
                        self.intrusion_numbers[i][app_idx].append(1)
                    elif src_ip in self.intrusion_ips[i][app_idx] and src_ip not in self.internal_hosts:
                        idx = self.intrusion_ips[i][app_idx].index(src_ip)
                        self.intrusion_numbers[i][app_idx][idx] += 1
                    if dst_ip not in self.intrusion_ips[i][app_idx] and dst_ip not in self.internal_hosts:
                        self.intrusion_ips[i].append(dst_ip)
                        self.intrusion_numbers[i][app_idx].append(1)
                    elif dst_ip in self.intrusion_ips[i][app_idx] and dst_ip not in self.internal_hosts:
                        idx = self.intrusion_ips[i][app_idx].index(dst_ip)
                        self.intrusion_numbers[i][app_idx][idx] += 1

    def _get_reward(self):

        before_count_deltas = self.in_samples_by_attacker_stack[-1] - self.in_samples_by_attacker_stack[0]
        after_count_deltas = self.out_samples_by_attacker_stack[-1] - self.out_samples_by_attacker_stack[0]
        normal = []
        attack = []
        for i in range(self.n_attackers + 1):
            b = before_count_deltas[i]
            a = after_count_deltas[i]
            if b > 0:
                blocked = np.clip(b - a, 0, b)
                allowed = np.clip(a, 0, b)
                if i < self.n_attackers:
                    attack.append(blocked / b)
                elif i == self.n_attackers:
                    normal.append(allowed / b)

        if len(normal) > 0:
            normal = np.mean(normal)
        else:
            normal = 1

        if len(attack) > 0:
            attack = np.mean(attack)
        else:
            attack = 0

        # count intrusions

        tp = 0
        fp = 0
        for intrusion_ips_by_ids, intrusion_numbers_by_ids in zip(self.intrusion_ips, self.intrusion_numbers):
            for intrusion_ips_by_app_and_ids, intrusion_numbers_by_app_and_ids in zip(intrusion_ips_by_ids, intrusion_numbers_by_ids):
                for ip, n in zip(intrusion_ips_by_app_and_ids, intrusion_numbers_by_app_and_ids):
                    if ip in attackers:
                        tp += n
                    else:
                        fp += n
        if (tp + fp) > 0:
            precision = tp / (tp + fp)
        else:
            precision = 0

        return normal, attack, precision

    def _action_mapper(self, i):

        if i < self.n_mirror_app_actions:
            action_array = np.zeros(self.n_mirror_app_actions)
            action_array[i] = 1
            action_array = action_array.reshape(self.n_apps, self.n_ids)
            app_i, ids_i = np.where(action_array == 1)
            app_idx = app_i[0]
            ids_idx = ids_i[0]
            ids_name = self.ids_vms[ids_idx]['vm']
            app = applications[app_idx]
            action_fun = mirror_app_to_ids
            args = (self.controller, self.ovs_node, ids_tables[ids_idx], priorities['lower'], priorities['medium'], app, 'ovs_{0}'.format(self.id), ids_name, self.tunnels)
            on_off_idx_and_value = (app_idx, ids_idx, 1)
        elif i < self.n_mirror_app_actions + self.n_unmirror_app_actions:
            action_array = np.zeros(self.n_unmirror_app_actions)
            action_array[i - self.n_mirror_app_actions] = 1
            action_array = action_array.reshape(self.n_apps, self.n_ids)
            app_i, ids_i = np.where(action_array == 1)
            app_idx = app_i[0]
            ids_idx = ids_i[0]
            app = applications[app_idx]
            action_fun = unmirror_app_from_ids
            args = (self.controller, self.ovs_node, ids_tables[ids_idx], app)
            on_off_idx_and_value = (app_idx, ids_idx, 0)
        elif i < self.n_mirror_app_actions + self.n_unmirror_app_actions + self.n_mirror_int_actions:
            e = np.eye(self.n_ids)
            action_array = np.zeros(self.n_mirror_int_actions)
            action_array[i - self.n_mirror_app_actions - self.n_unmirror_app_actions] = 1
            action_array = action_array.reshape(self.n_apps, self.n_ids, self.n_ids - 1)
            app_i, ids_from, ids_to_ = np.where(action_array == 1)
            ids_from = ids_from[0]
            ids_to = np.where(e[ids_from] == 0)[0][ids_to_[0]]
            ids_name = self.ids_vms[ids_to]['vm']
            app_idx = app_i[0]
            app = applications[app_idx]
            ips = self.intrusion_ips[ids_from][app_idx]
            action_fun = mirror_ip_app_to_ids
            args = (self.controller, self.ovs_node, ids_tables[ids_to], priorities['higher'], priorities['highest'], ips, app, 'ovs_{0}'.format(self.id), ids_name, self.tunnels)
            on_off_idx_and_value = (app_idx, self.n_ids + ids_from * (self.n_ids - 1) + ids_to_[0], 1)
        elif i < self.n_mirror_app_actions + self.n_unmirror_app_actions + self.n_mirror_int_actions + self.n_unmirror_int_actions:
            e = np.eye(self.n_ids)
            action_array = np.zeros(self.n_mirror_int_actions)
            action_array[i - self.n_mirror_app_actions - self.n_unmirror_app_actions - self.n_mirror_int_actions] = 1
            action_array = action_array.reshape(self.n_apps, self.n_ids, self.n_ids - 1)
            app_i, ids_from, ids_to_ = np.where(action_array == 1)
            ids_from = ids_from[0]
            ids_to = np.where(e[ids_from] == 0)[0][ids_to_[0]]
            app_idx = app_i[0]
            app = applications[app_idx]
            ips = self.intrusion_ips[ids_from][app_idx]
            action_fun = unmirror_ip_app_from_ids
            args = (self.controller, self.ovs_node, ids_tables[ids_to], ips, app)
            on_off_idx_and_value = (app_idx, self.n_ids + ids_from * (self.n_ids - 1) + ids_to_[0], 0)
        elif i < self.n_mirror_app_actions + self.n_unmirror_app_actions + self.n_mirror_int_actions + self.n_unmirror_int_actions + self.n_block_actions:
            action_array = np.zeros(self.n_block_actions)
            action_array[i - self.n_mirror_app_actions - self.n_unmirror_app_actions - self.n_mirror_int_actions - self.n_unmirror_int_actions] = 1
            action_array = action_array.reshape(self.n_apps, self.n_ids)
            app_i, ids_i = np.where(action_array == 1)
            app_idx = app_i[0]
            ids_idx = ids_i[0]
            ips = self.intrusion_ips[ids_idx][app_idx]
            app = applications[app_idx]
            action_fun = block_ip_app
            args = (self.controller, self.ovs_node, block_table, priorities['higher'], priorities['highest'], ips, app)
            if self.debug:
                if len(app) == 2:
                    for ip in ips:
                        print('Blocking {0}:{1}:{2} in {3}'.format(app[0], ip, app[1], self.id))
                elif len(app) == 1:
                    for ip in ips:
                        print('Blocking {0}:{1}:all in {2}'.format(app[0], ip, self.id))
            on_off_idx_and_value = (app_idx, self.n_ids ** 2 + ids_idx, 1)
        elif i < self.n_mirror_app_actions + self.n_unmirror_app_actions + self.n_mirror_int_actions + self.n_unmirror_int_actions + self.n_block_actions + self.n_unblock_actions:
            action_array = np.zeros(self.n_unblock_actions)
            action_array[i - self.n_mirror_app_actions - self.n_unmirror_app_actions - self.n_mirror_int_actions - self.n_unmirror_int_actions - self.n_block_actions] = 1
            action_array = action_array.reshape(self.n_apps, self.n_ids)
            app_i, ids_i = np.where(action_array == 1)
            app_idx = app_i[0]
            ids_idx = ids_i[0]
            ips = self.intrusion_ips[ids_idx][app_idx]
            app = applications[app_idx]
            action_fun = unblock_ip_app
            args = (self.controller, self.ovs_node, block_table, ips, app)
            on_off_idx_and_value = (app_idx, self.n_ids ** 2 + ids_idx, 0)
        elif i < self.n_mirror_app_actions + self.n_unmirror_app_actions + self.n_mirror_int_actions + self.n_unmirror_int_actions + self.n_block_actions + self.n_unblock_actions + self.n_ids_actions:
            action_array = np.zeros(self.n_ids_actions)
            action_array[i - self.n_mirror_app_actions - self.n_unmirror_app_actions - self.n_mirror_int_actions - self.n_unmirror_int_actions - self.n_block_actions - self.n_unblock_actions] = 1
            action_array = action_array.reshape(self.n_ids, self.n_models + self.n_steps)
            ids_i, value_i = np.where(action_array == 1)
            ids_idx = ids_i[0]
            value = value_i[0]
            ids_ip = self.ids_vms[ids_idx]['ip']
            if value < self.n_models:
                param = 'model'
                value = int(value)
            else:
                param = 'step'
                value = int(value) - self.n_models
            action_fun = set_vnf_param
            args = (ids_ip, flask_port, param, value)
            on_off_idx_and_value = None
        else:
            action_fun = lambda *args: None
            args = ()
            on_off_idx_and_value = None
        return action_fun, args, on_off_idx_and_value

    def _take_action(self, i):
        func, args, on_off_idx_and_value = self._action_mapper(i)
        func(*args)
        if on_off_idx_and_value is not None:
            app_i, j, val = on_off_idx_and_value
            self.on_off_frame[app_i, j] = val

    def _rearange_counts(self, flows, counts, flows_r):
        counts_r = np.zeros_like(counts)
        for i in range(len(flows_r)):
            if flows_r[i] in flows:
                idx = flows.index(flows_r[i])
                counts_r[i] = counts[idx]
        return counts_r

    def reset(self, sleep_duration=1):

        # end of the episode

        tnow = time()
        if self.tstart is not None:
            print('Episode duration: {0}'.format(tnow - self.tstart))

        # reset ids

        for i in range(self.n_ids):
            reset_ids(self.ids_vms[i]['mgmt'], flask_port)
        self.intrusion_ips = [[[] for _ in range(self.n_apps)] for __ in range(self.n_ids)]
        self.intrusion_numbers = [[[] for _ in range(self.n_apps)] for __ in range(self.n_ids)]

        # reset tables

        init_ovs_tables(self.controller, self.ovs_node, self.veths)

        # wait for sdn configuration to be processed

        tables = np.arange(in_table, out_table)
        for table in tables:
            flows, counts = get_flow_counts(self.controller, self.ovs_node, table)
            while len(flows) != 1:
                sleep(sleep_duration)
                flows, counts = get_flow_counts(self.controller, self.ovs_node, table)

        # set time

        if self.tstart is not None:
            tnow = time()
            if (tnow - self.tstart) < episode_duration:
                sleep(episode_duration - (tnow - self.tstart))

        # default reset actions

        if self.default_reset_actions is not None:
            for action in self.default_reset_actions:
                self._take_action(action)

        # generate traffic

        for host in self.internal_hosts:
            generate_ip_traffic_on_interface(self.ovs_vm['mgmt'], flask_port, host, self.label, episode_duration)

        self.tstart = time()
        self.tstep = time()

        # calculate obs

        in_samples, out_samples = get_flow_samples(self.ovs_vm['ip'], flask_port, flow_window)
        in_samples_by_app = self._process_app_samples(in_samples)
        out_samples_by_app = self._process_app_samples(out_samples)
        in_samples_by_attacker = self._process_reward_samples(in_samples)
        out_samples_by_attacker = self._process_reward_samples(out_samples)
        frame = np.hstack([
            in_samples_by_app,
            out_samples_by_app,
            np.zeros((self.n_apps, self.n_ids)),
            np.array(self.on_off_frame)
        ])
        self.app_counts_stack.append(frame)
        self.in_samples_by_attacker_stack.append(in_samples_by_attacker)
        self.out_samples_by_attacker_stack.append(out_samples_by_attacker)

        while len(self.app_counts_stack) < self.app_counts_stack.maxlen:

            in_samples, out_samples = get_flow_samples(self.ovs_vm['ip'], flask_port, flow_window)
            in_samples_by_app = self._process_app_samples(in_samples)
            out_samples_by_app = self._process_app_samples(out_samples)
            frame = np.hstack([
                in_samples_by_app,
                out_samples_by_app,
                np.zeros((self.n_apps, self.n_ids)),
                np.array(self.on_off_frame)
            ])
            self.app_counts_stack.append(frame)
            self.in_samples_by_attacker_stack.append(in_samples_by_attacker)
            self.out_samples_by_attacker_stack.append(out_samples_by_attacker)

        obs = np.array(self.app_counts_stack)

        return obs

    def step(self, action):

        # take an action and measure time

        if self.default_step_actions is not None:
            for action in self.default_step_actions:
                self._take_action(action)
        else:
            self._take_action(action)
        tnow = time()
        if (tnow - self.tstep) < self.step_duration:
            sleep(self.step_duration - (tnow - self.tstep))
        self.tstep = time()

        # obs

        in_samples, out_samples = get_flow_samples(self.ovs_vm['ip'], flask_port, flow_window)
        in_samples_by_app = self._process_app_samples(in_samples)
        out_samples_by_app = self._process_app_samples(out_samples)
        processed_counts = []
        processed_counts.append(in_samples_by_app)
        processed_counts.append(out_samples_by_app)
        nintrusions = np.zeros((self.n_apps, self.n_ids))
        for i in range(self.n_apps):
            for j in range(self.n_ids):
                nintrusions[i, j] = np.sum(self.intrusion_numbers[j][i])
        processed_counts.append(nintrusions)
        processed_counts.append(np.array(self.on_off_frame))
        frame = np.hstack(processed_counts)
        self.app_counts_stack.append(frame)
        obs = np.array(self.app_counts_stack)

        # intrusions

        self._update_intrusions()

        # reward

        in_samples_by_attacker = self._process_reward_samples(in_samples)
        out_samples_by_attacker = self._process_reward_samples(out_samples)
        self.in_samples_by_attacker_stack.append(in_samples_by_attacker)
        self.out_samples_by_attacker_stack.append(out_samples_by_attacker)
        normal, attack, precision = self._get_reward()
        reward = normal + attack + precision - 1

        done = False
        return obs, reward, done, {'r': reward, 'n': normal, 'a': attack, 'p': precision}