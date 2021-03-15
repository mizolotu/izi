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
from reinforcement_learning.gym.envs.reactive1.sdn_state import get_flow_counts
from reinforcement_learning.gym.envs.reactive1.nfv_state import get_intrusions
from reinforcement_learning.gym.envs.reactive1.generate_traffic import calculate_probs, replay_pcap, select_file

class AttackMitigationEnv():

    def __init__(self, env_id, label, nsteps):

        # id

        self.id = env_id

        # load logs

        with open(vms_fpath, 'r') as f:
            self.vms = json.load(f)

        with open(nodes_fpath, 'r') as f:
            self.nodes = json.load(f)

        with open(tunnels_fpath, 'r') as f:
            self.tunnels = json.load(f)

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
        ovs_vm = ovs_vms[0]
        self.ovs_node = self.nodes[ovs_vm['vm']]

        # ids vms

        self.ids_vms = [vm for vm in self.vms if vm['role'] == 'ids' and int(vm['vm'].split('_')[1]) == self.id]
        self.n_ids = len(self.ids_vms)
        self.ids_nodes = [self.nodes[vm['vm']] for vm in self.ids_vms]
        assert (self.n_ids + 4) <= ntables
        for vm in self.ids_vms:
            restart_ids(vm)

        # controller

        controller_vm = [vm for vm in self.vms if vm['role'] == 'sdn']
        assert len(controller_vm) == 1
        controller_name = controller_vm[0]['vm']
        controller_ip = controller_vm[0]['ip']
        if controller_name == ctrl_name:
            self.controller = Odl(controller_ip)

        # init tables

        self.internal_hosts = sorted([item.split(csv_postfix)[0] for item in os.listdir(spl_dir) if osp.isfile(osp.join(spl_dir, item)) and item.endswith(csv_postfix)])
        clean_ids_tables(self.controller, self.ids_nodes)

        # time

        self.tstart = None
        self.step_duration = episode_duration / nsteps

        # traffic

        self.label = label
        self.profiles = calculate_probs(spl_dir)

        # actions

        self.n_apps = len(applications)
        self.n_mirror_app_actions = self.n_apps * self.n_ids
        self.n_unmirror_app_actions = self.n_apps * self.n_ids
        self.n_mirror_int_actions = self.n_apps * (self.n_ids - 1) * self.n_ids
        self.n_unmirror_int_actions = self.n_apps * (self.n_ids - 1) * self.n_ids
        self.n_block_actions = self.n_apps * self.n_ids
        self.n_unblock_actions = self.n_apps * self.n_ids
        self.n_ids_actions = (self.n_models + self.n_steps) * self.n_ids
        act_dim = self.n_mirror_app_actions + self.n_unmirror_app_actions + self.n_mirror_int_actions + self.n_unmirror_int_actions + \
                  self.n_block_actions + self.n_unblock_actions + self.n_ids_actions + 1
        self.intrusions = [[[] for _ in range(self.n_apps)] for __ in range(self.n_ids)]

        # obs

        self.stack_size = 16
        obs_shape = (self.stack_size, self.n_apps, (1 + (self.n_ids + 1) * 2))
        self.app_counts_stack = deque(maxlen=self.stack_size)
        self.before_counts_stack = deque(maxlen=self.stack_size)
        self.after_counts_stack = deque(maxlen=self.stack_size)

        # reward

        self.n_attackers = len(attackers)

        # spaces

        self.observation_space = spaces.Box(low=0, high=np.inf, shape=obs_shape, dtype=np.float32)
        self.action_space = spaces.Discrete(act_dim)
        print(obs_shape, act_dim)

    def _get_counts(self, table):
        flows, counts = get_flow_counts(self.controller, self.ovs_node, table)
        return flows, counts

    def _process_app_counts(self, flows, counts, count_ips=False):
        if count_ips:
            uips = [[] for _ in range(self.n_apps)]
            x = np.zeros((self.n_apps, 2))
            for f, c in zip(flows, counts):
                if f.startswith('iippp'):
                    spl = f.split('_')
                    ip = spl[2]
                    app = (spl[3], int(spl[5]))
                    app_idx = applications.index(app)
                    if ip not in uips[app_idx]:
                        uips[app_idx].append(ip)
                    x[app_idx, 0] += c
                    x[app_idx, 1] = len(uips[app_idx])
                elif f.startswith('iip'):
                    spl = f.split('_')
                    ip = spl[2]
                    app = (spl[3],)
                    app_idx = applications.index(app)
                    if ip not in uips[app_idx]:
                        uips[app_idx].append(ip)
                    x[app_idx, 0] += c
                    x[app_idx, 1] = len(uips[app_idx])
        else:
            x = np.zeros((self.n_apps, 1))
            for f, c in zip(flows, counts):
                if f.startswith('ppp'):
                    spl = f.split('_')
                    app = (spl[1], int(spl[3]))
                    idx = applications.index(app)
                    x[idx, 0] += c
                elif f.startswith('p'):
                    spl = f.split('_')
                    app = (spl[1], )
                    idx = applications.index(app)
                    x[idx, 0] += c
        return x

    def _process_reward_counts(self, flows, counts):
        x = np.zeros((self.n_attackers + 1, 1))
        for f, c in zip(flows, counts):
            if f.startswith('ii'):
                spl = f.split('_')
                ip = spl[2]
                idx = attackers.index(ip)
            elif f.startswith('def'):
                idx = -1
            x[idx] += c
        return x

    def _update_intrusions(self):
        for i in range(self.n_ids):
            intrusions = get_intrusions(self.ids_vms[i]['ip'])
            new_intrusions = [[] for _ in range(self.n_apps)]
            for intrusion in intrusions:
                src_ip = intrusion[0]
                src_port = intrusion[1]
                dst_ip = intrusion[2]
                dst_port = intrusion[3]
                proto, proto_number = ip_proto(intrusion[4])
                if (proto, src_port) in applications:
                    app_idx = applications.index((proto, src_port))
                elif (proto, dst_port) in applications:
                    app_idx = applications.index((proto, dst_port))
                else:
                    app_idx = applications.index((proto,))
                if src_ip not in new_intrusions[app_idx] and src_ip not in self.internal_hosts:
                    new_intrusions[app_idx].append(src_ip)
                if dst_ip not in new_intrusions[app_idx] and dst_ip not in self.internal_hosts:
                    new_intrusions.append(dst_ip)
                self.intrusions[i][app_idx] = list(set(self.intrusions[i][app_idx] + new_intrusions[app_idx]))

    def _get_reward(self):

        before_count_deltas = self.before_counts_stack[-1] - self.before_counts_stack[0]
        after_count_deltas = self.after_counts_stack[-1] - self.after_counts_stack[0]
        normal = []
        attack = []
        fa = []
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

        intrusions = []
        for intrusions_by_ids in self.intrusions:
            for intrusions_by_app_and_ids in intrusions_by_ids:
                intrusions = list(set(intrusions + intrusions_by_app_and_ids))
        bonus = 0
        for intrusion in intrusions:
            if intrusion in attackers:
                bonus += 1.0 / self.n_attackers
            else:
                bonus -= 1.0 / self.n_attackers

        return normal, attack, bonus

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
            args = (self.controller, self.ovs_node, ids_tables[ids_idx], priorities['lower'], priorities['medium'], app, self.tunnels, 'ovs_{0}'.format(self.id), ids_name)
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
        elif i < self.n_mirror_app_actions + self.n_unmirror_app_actions + self.n_mirror_int_actions:
            e = np.eye(self.n_ids)
            action_array = np.zeros(self.n_mirror_int_actions)
            action_array[i - self.n_mirror_app_actions - self.n_unmirror_app_actions] = 1
            action_array = action_array.reshape(self.n_apps, self.n_ids, self.n_ids - 1)
            app_i, ids_from, ids_to = np.where(action_array == 1)
            ids_from = ids_from[0]
            ids_to = np.where(e[ids_from] == 0)[0][ids_to[0]]
            ids_name = self.ids_vms[ids_to]['vm']
            app_idx = app_i[0]
            app = applications[app_idx]
            ips = self.intrusions[ids_from][app_idx]
            action_fun = mirror_ip_app_to_ids
            args = (self.controller, self.ovs_node, ids_tables[ids_to], priorities['higher'], priorities['highest'], ips, app, self.tunnels, 'ovs_{0}'.format(self.id), ids_name)
        elif i < self.n_mirror_app_actions + self.n_unmirror_app_actions + self.n_mirror_int_actions + self.n_unmirror_int_actions:
            e = np.eye(self.n_ids)
            action_array = np.zeros(self.n_mirror_int_actions)
            action_array[i - self.n_mirror_app_actions - self.n_unmirror_app_actions - self.n_mirror_int_actions] = 1
            action_array = action_array.reshape(self.n_apps, self.n_ids, self.n_ids - 1)
            app_i, ids_from, ids_to = np.where(action_array == 1)
            ids_from = ids_from[0]
            ids_to = np.where(e[ids_from] == 0)[0][ids_to[0]]
            app_idx = app_i[0]
            app = applications[app_idx]
            ips = self.intrusions[ids_from][app_idx]
            action_fun = unmirror_ip_app_from_ids
            args = (self.controller, self.ovs_node, ids_tables[ids_to], ips, app)
        elif i < self.n_mirror_app_actions + self.n_unmirror_app_actions + self.n_mirror_int_actions + self.n_unmirror_int_actions + self.n_block_actions:
            action_array = np.zeros(self.n_block_actions)
            action_array[i - self.n_mirror_app_actions - self.n_unmirror_app_actions - self.n_mirror_int_actions - self.n_unmirror_int_actions] = 1
            action_array = action_array.reshape(self.n_apps, self.n_ids)
            app_i, ids_i = np.where(action_array == 1)
            app_idx = app_i[0]
            ids_idx = ids_i[0]
            ips = self.intrusions[ids_idx][app_idx]
            app = applications[app_idx]
            action_fun = block_ip_app
            args = (self.controller, self.ovs_node, block_table, priorities['higher'], priorities['highest'], ips, app)
        elif i < self.n_mirror_app_actions + self.n_unmirror_app_actions + self.n_mirror_int_actions + self.n_unmirror_int_actions + self.n_block_actions + self.n_unblock_actions:
            action_array = np.zeros(self.n_unblock_actions)
            action_array[i - self.n_mirror_app_actions - self.n_unmirror_app_actions - self.n_mirror_int_actions - self.n_unmirror_int_actions - self.n_block_actions] = 1
            action_array = action_array.reshape(self.n_apps, self.n_ids)
            app_i, ids_i = np.where(action_array == 1)
            app_idx = app_i[0]
            ids_idx = ids_i[0]
            ips = self.intrusions[ids_idx][app_idx]
            app = applications[app_idx]
            action_fun = unblock_ip_app
            args = (self.controller, self.ovs_node, block_table, ips, app)
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
            args = (ids_ip, param, value)
        else:
            action_fun = lambda *args: None
            args = ()
        return action_fun, args

    def _take_action(self, i):
        func, args = self._action_mapper(i)
        func(*args)

    def _rearange_counts(self, flows, counts, flows_r):
        counts_r = np.zeros_like(counts)
        for i in range(len(flows_r)):
            if flows_r[i] in flows:
                idx = flows.index(flows_r[i])
                counts_r[i] = counts[idx]
        return counts_r

    def reset(self, sleep_duration=1):

        # reset ids

        for i in range(self.n_ids):
            reset_ids(self.ids_vms[i]['mgmt'])
        self.intrusions = [[[] for _ in range(self.n_apps)] for __ in range(self.n_ids)]

        # reset tables

        init_ovs_tables(self.controller, self.ovs_node)

        # wait for sdn configuration to be processed

        tables = [app_table, reward_tables[0], reward_tables[1]]
        conditions = [self.n_apps * 2 - 1, len(attackers) * 2 + 1, len(attackers) * 2 + 1]
        for table, condition in zip(tables, conditions):
            flows, counts = get_flow_counts(self.controller, self.ovs_node, table)
            while len(flows) != condition:
                sleep(sleep_duration)
                flows, counts = get_flow_counts(self.controller, self.ovs_node, table)

        # set time

        if self.tstart is not None:
            tnow = time()
            if (tnow - self.tstart) < episode_duration:
                sleep(episode_duration - (tnow - self.tstart))

        # sample files

        for p in self.profiles:
            fpath = select_file(p, self.label)
            replay_pcap(fpath, traffic_generation_ifaces[self.id])

        self.tstart = time()

        # calculate obs

        app_flows, app_counts = self._get_counts(app_table)
        before_flows, before_counts = self._get_counts(reward_tables[0])
        after_flows, after_counts = self._get_counts(reward_tables[1])

        processed_app_counts = self._process_app_counts(app_flows, app_counts)
        processed_before_counts = self._process_reward_counts(before_flows, before_counts)
        processed_after_counts = self._process_reward_counts(after_flows, after_counts)

        frame = np.hstack([processed_app_counts, np.zeros((self.n_apps, 2 * (self.n_ids + 1)))])
        self.app_counts_stack.append(frame)
        self.before_counts_stack.append(processed_before_counts)
        self.after_counts_stack.append(processed_after_counts)

        while len(self.app_counts_stack) < self.app_counts_stack.maxlen:

            app_flows, app_counts = self._get_counts(app_table)
            before_flows, before_counts = self._get_counts(reward_tables[0])
            after_flows, after_counts = self._get_counts(reward_tables[1])

            processed_app_counts = self._process_app_counts(app_flows, app_counts)
            processed_before_counts = self._process_reward_counts(before_flows, before_counts)
            processed_after_counts = self._process_reward_counts(after_flows, after_counts)

            frame = np.hstack([processed_app_counts, np.zeros((self.n_apps, 2 * (self.n_ids + 1)))])
            self.app_counts_stack.append(frame)
            self.before_counts_stack.append(processed_before_counts)
            self.after_counts_stack.append(processed_after_counts)

        obs = np.array(self.app_counts_stack)

        return obs

    def step(self, action):

        # take an action and measure time

        tstart = time()
        self._take_action(action)
        tnow = time()
        if (tnow - tstart) < self.step_duration:
            sleep(self.step_duration - (tnow - tstart))

        # get and process counts

        app_flows, app_counts = self._get_counts(app_table)
        before_flows, before_counts = self._get_counts(reward_tables[0])
        after_flows, after_counts = self._get_counts(reward_tables[1])

        processed_counts = []
        processed_counts.append(self._process_app_counts(app_flows, app_counts))
        for i in range(self.n_ids):
            flows, counts = self._get_counts(ids_tables[i])
            processed_counts.append(self._process_app_counts(flows, counts, count_ips=True))
        flows, counts = self._get_counts(block_table)
        processed_counts.append(self._process_app_counts(flows, counts, count_ips=True))
        frame = np.hstack(processed_counts)

        processed_before_counts = self._process_reward_counts(before_flows, before_counts)
        processed_after_counts = self._process_reward_counts(after_flows, after_counts)

        self.app_counts_stack.append(frame)
        self.before_counts_stack.append(processed_before_counts)
        self.after_counts_stack.append(processed_after_counts)

        # get intrusions

        self._update_intrusions()

        # get obs

        obs = np.array(self.app_counts_stack)

        # get reward

        normal, attack, bonus = self._get_reward()
        reward = normal + attack + bonus - 1

        done = False
        return obs, reward, done, {'r': reward, 'n': normal, 'a': attack, 'b': bonus}