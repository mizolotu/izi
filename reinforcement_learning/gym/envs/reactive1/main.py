import json, os
import os.path as osp
import numpy as np

from reinforcement_learning.gym import spaces
from config import *
from time import sleep, time
from common.odl import Odl
from collections import deque

from reinforcement_learning.gym.envs.reactive1.init_flow_tables import clean_ids_tables, init_ovs_tables
from reinforcement_learning.gym.envs.reactive1.sdn_actions import mirror_app_to_ids, mirror_ip_to_ids, block_ip
from reinforcement_learning.gym.envs.reactive1.nfv_actions import set_vnf_param, reset_ids
from reinforcement_learning.gym.envs.reactive1.sdn_state import get_flow_counts
from reinforcement_learning.gym.envs.reactive1.nfv_state import get_vnf_param, get_intrusions
from reinforcement_learning.gym.envs.reactive1.generate_traffic import calculate_probs, replay_pcap, select_file

class AttackMitigationEnv():

    def __init__(self, label, nsteps):

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

        ovs_vms = sorted([vm for vm in self.vms if vm['role'] == 'ovs'])
        assert len(ovs_vms) == 1
        ovs_vm = ovs_vms[0]
        self.ovs_node = self.nodes[ovs_vm['vm']]

        # ids vms

        self.ids_vms = [vm for vm in self.vms if vm['role'] == 'ids']
        self.n_ids = len(self.ids_vms)
        self.ids_nodes = [self.nodes[vm['vm']] for vm in self.ids_vms]
        assert (self.n_ids + 5) <= ntables

        # controller

        controller_vm = [vm for vm in self.vms if vm['role'] == 'sdn']
        assert len(controller_vm) == 1
        controller_name = controller_vm[0]['vm']
        controller_ip = controller_vm[0]['ip']
        if controller_name == 'odl':
            self.controller = Odl(controller_ip)

        # init tables

        self.internal_hosts = sorted([item.split(csv_postfix)[0] for item in os.listdir(samples_dir) if osp.isfile(osp.join(samples_dir, item)) and item.endswith(csv_postfix)])
        clean_ids_tables(self.controller, self.ids_nodes)

        # time

        self.tstart = None
        self.step_duration = episode_duration / nsteps

        # traffic

        self.label = label
        self.profiles = calculate_probs(samples_dir)

        # actions

        self.n_apps = len(applications)
        self.n_mirror_actions = (self.n_apps + (self.n_ids - 1)) * self.n_ids
        self.n_block_actions = self.n_ids
        self.n_ids_actions = (self.n_models + self.n_steps) * self.n_ids
        self.actions_on_off = np.zeros(self.n_mirror_actions + self.n_block_actions)
        self.n_on_off = len(self.actions_on_off)
        act_dim = self.n_on_off + self.n_ids_actions + 1
        self.intrusions = [[] for _ in range(self.n_ids)]

        # obs

        maxlen = 16
        obs_dim = (self.n_apps + 1) * 2 + self.n_ids * (n_ids_params + 1) + self.n_on_off
        self.app_counts_stack = deque(maxlen=maxlen)
        self.before_counts_stack = deque(maxlen=maxlen)
        self.after_counts_stack = deque(maxlen=maxlen)

        # reward

        self.n_attackers = len(attackers)

        # spaces

        self.observation_space = spaces.Box(low=0, high=np.inf, shape=(obs_dim,), dtype=np.float32)
        self.action_space = spaces.Discrete(act_dim)

    def _get_counts(self):

        # obs

        app_flows, app_counts = get_flow_counts(self.controller, self.ovs_node, app_table)

        # reward

        reward_flows, reward_counts_before = get_flow_counts(self.controller, self.ovs_node, reward_tables[0])
        reward_flows_after, reward_counts_after_ = get_flow_counts(self.controller, self.ovs_node, reward_tables[1])
        #assert len(reward_flows) == len(reward_flows_after)
        reward_counts_after = np.zeros_like(reward_counts_before)
        for i in range(len(reward_flows)):
            if reward_flows[i] in reward_flows_after:
                idx = reward_flows_after.index(reward_flows[i])
                reward_counts_after[i] = reward_counts_after_[idx]

        return app_flows, app_counts, reward_flows, reward_counts_before, reward_counts_after

    def _update_intrusions(self):
        for i in range(self.n_ids):
            intrusions = get_intrusions(self.ids_vms[i]['ip'])
            new_intrusions = []
            for intrusion in intrusions:
                if intrusion[0] not in new_intrusions and intrusion[0] not in self.internal_hosts:
                    new_intrusions.append(intrusion[0])
                if intrusion[2] not in new_intrusions and intrusion[2] not in self.internal_hosts:
                    new_intrusions.append(intrusion[2])
            self.intrusions[i] = list(set(self.intrusions[i] + new_intrusions))
            #if len(self.intrusions[i]) > 0:
            #    print(i, self.intrusions[i])

    def _get_obs(self):

        app_count_deltas = self.app_counts_stack[-1] - self.app_counts_stack[0]
        ids_obs = np.zeros((self.n_ids, n_ids_params + 1))
        for i in range(self.n_ids):
            for j in range(n_ids_params + 1):
                if j < n_ids_params:
                    ids_obs[i, j] = get_vnf_param(self.ids_vms[i]['mgmt'], ids_params[j])
                else:
                    ids_obs[i, j] = len(self.intrusions[i])

        obs = np.hstack([
            app_count_deltas,
            ids_obs.reshape(1, - 1)[0],
            self.actions_on_off
        ])

        return obs

    def _get_reward(self):

        before_count_deltas = self.before_counts_stack[-1] - self.before_counts_stack[0]
        after_count_deltas = self.after_counts_stack[-1] - self.after_counts_stack[0]
        normal = []
        attack = []
        fa = []
        for f, b, a in zip(self.reward_flows, before_count_deltas, after_count_deltas):
            if b > 0:
                blocked = np.clip(b - a, 0, b)
                allowed = np.clip(a, 0, b)
                if f.startswith('source') or f.startswith('destination'):
                    attack.append(blocked / b)
                    fa.append(f)
                elif f.startswith('proto'):
                    normal.append(allowed / b)
                else:
                    print(f)

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
        for intrusion_list in self.intrusions:
            intrusions = list(set(intrusions + intrusion_list))
        bonus = 0
        for intrusion in intrusions:
            if intrusion in attackers:
                bonus += 1.0 / len(attackers)
            else:
                bonus -= 1.0 / len(attackers)

        return normal, attack, bonus

    def _action_mapper(self, i):

        if i < self.n_mirror_actions:
            e = np.eye(self.n_ids)
            action_array = np.zeros(self.n_mirror_actions)
            action_array[i] = 1
            action_array = action_array.reshape(self.n_apps + (self.n_ids - 1), self.n_ids)
            app_i, ids_i = np.where(action_array == 1)
            ids_name = self.ids_vms[ids_i[0]]['vm']
            if app_i[0] < self.n_apps:
                app = applications[app_i[0]]
                action_fun = mirror_app_to_ids
            else:
                app = self.intrusions[np.where(e[ids_i[0]] == 0)[0][app_i[0] - self.n_apps]]
                action_fun = mirror_ip_to_ids
            args = (self.controller, self.ovs_node, ids_tables[ids_i[0]], priorities['high'], app, ids_name, self.tunnels)
            self.actions_on_off[i] = 1 - self.actions_on_off[i]
        elif i < self.n_mirror_actions + self.n_block_actions:
            ids_i = i - self.n_mirror_actions
            ips = self.intrusions[ids_i]
            action_fun = block_ip
            args = (self.controller, self.ovs_node, block_table, priorities['high'], ips)
            self.actions_on_off[i] = 1 - self.actions_on_off[i]
        elif i < self.n_mirror_actions + self.n_block_actions + self.n_ids_actions:
            i = i - self.n_mirror_actions - self.n_block_actions
            action_array = np.zeros(self.n_ids * (self.n_models + self.n_steps))
            action_array[i] = 1
            action_array = action_array.reshape(self.n_models + self.n_steps, self.n_ids)
            value_i, ids_i = np.where(action_array == 1)
            ids_ip = self.ids_vms[ids_i[0]]['ip']
            if value_i[0] < self.n_models:
                param = 'model'
                value = int(value_i[0])
            else:
                param = 'step'
                value = int(value_i[0]) - self.n_models
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
        self.intrusions = [[] for _ in range(self.n_ids)]

        # reset tables

        init_ovs_tables(self.controller, self.ovs_node, self.internal_hosts)

        # reset on off

        self.actions_on_off = np.zeros(self.n_mirror_actions + self.n_block_actions)

        # wait for sdn configuration to be processed

        tables = [app_table, reward_tables[0], reward_tables[1]]
        conditions = [(self.n_apps + 1) * 2, (len(attackers) + 1) * 2, (len(attackers) + 1) * 2]
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
            replay_pcap(fpath, traffic_generation_iface)

        self.tstart = time()

        # calculate obs

        self.app_flows, app_counts, self.reward_flows, reward_counts_before, reward_counts_after = self._get_counts()
        self.app_counts_stack.append(app_counts)
        self.before_counts_stack.append(reward_counts_before)
        self.after_counts_stack.append(reward_counts_after)
        while len(self.app_counts_stack) < self.app_counts_stack.maxlen:
            app_flows, app_counts, reward_flows, reward_counts_before, reward_counts_after = self._get_counts()
            app_counts = self._rearange_counts(app_flows, app_counts, self.app_flows)
            reward_counts_before = self._rearange_counts(reward_flows, reward_counts_before, self.reward_flows)
            reward_counts_after = self._rearange_counts(reward_flows, reward_counts_after, self.reward_flows)
            self.app_counts_stack.append(app_counts)
            self.before_counts_stack.append(reward_counts_before)
            self.after_counts_stack.append(reward_counts_after)

        obs = self._get_obs()

        return obs

    def step(self, action):
        tstart = time()
        self._take_action(action)
        tnow = time()
        if (tnow - tstart) < self.step_duration:
            sleep(self.step_duration - (tnow - tstart))

        # get counts

        app_flows, app_counts, reward_flows, reward_counts_before, reward_counts_after = self._get_counts()

        # rearrange counts

        app_counts = self._rearange_counts(app_flows, app_counts, self.app_flows)
        reward_counts_before = self._rearange_counts(reward_flows, reward_counts_before, self.reward_flows)
        reward_counts_after = self._rearange_counts(reward_flows, reward_counts_after, self.reward_flows)

        # add counts to stacks

        self.app_counts_stack.append(app_counts)
        self.before_counts_stack.append(reward_counts_before)
        self.after_counts_stack.append(reward_counts_after)

        # get intrusions

        self._update_intrusions()

        # get obs

        obs = self._get_obs()

        # get reward

        normal, attack, bonus = self._get_reward()
        reward = normal + attack + bonus - 1

        done = False
        return obs, reward, done, {'r': reward, 'n': normal, 'a': attack, 'b': bonus}