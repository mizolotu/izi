import os
import argparse as arp
import pandas as pd
import os.path as osp
import numpy as np

from reinforcement_learning.gym.envs.reactive_sfc.main import ReactiveDiscreteEnv
from reinforcement_learning.common.vec_env.subproc_vec_env import SubprocVecEnv
from config import *
from common.ml import load_meta
from common import data
from threading import Thread
from queue import Queue

def make_env(env_class, *args):
    fn = lambda: env_class(*args)
    return fn

def run_env(env, idx, action, nsteps, q):
    for i in range(nsteps):
        obs, rew, done, info = env.step_one(idx, action)
        q.put(info['features'])

def dump_data(q, fpath, nmax):
    n = 0
    while n < nmax:
        if not q.empty():
            try:
                x = q.get()
                labels = x[:, -1]
                np.where(labels > 0)[0]
            except:
                pass


if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Test agent.')
    parser.add_argument('-e', '--environment', help='Environment name', default='ReactiveDiscreteEnv')
    parser.add_argument('-r', '--reset', help='Default reset actions',nargs='+', type=int, default=[0, 1])
    parser.add_argument('-a', '--action', help='Default step action', type=int, default=[23])
    parser.add_argument('-l', '--label', help='Attack label', type=int, default=1)
    parser.add_argument('-u', '--augment', help='Augment the data?', default=False, type=bool)
    parser.add_argument('-n', '--nenvs', help='Number of environments', default=nenvs, type=int)
    parser.add_argument('-s', '--size', help='Number of malicious samples', default=100000, type=int)
    parser.add_argument('-v', '--reverse_labeler', help='Reverse labeler', default='reverse_label_cicids')
    args = parser.parse_args()

    # reverse labeler

    reverse_labeler = getattr(data, args.reverse_labeler)

    # handle attack index

    meta = load_meta(data_dir)
    attack_labels = sorted([label for label in meta['labels'] if label > 0])
    assert args.label in attack_labels, f'Can not find label {args.label} in the data!'
    attack_ips, attack_directions = reverse_labeler(args.label)
    attack_data = {args.label: (attack_ips, attack_directions)}
    attacks = [args.label]

    # create environment

    env_class = locals()[args.environment]
    default_policy = {'reset': args.reset, 'step': None}
    env_fns = [make_env(env_class, env_idx, attacks, attack_data, args.augment, seed, default_policy) for env_idx in range(nenvs)]
    env = SubprocVecEnv(env_fns)

    # dump features

    q = Queue()
    th = Thread(target=dump_data, args=(q, ''), daemon=True)
    th.start()

    # runner

    actions = np.array([args.action for _ in range(nenvs)])
    env.reset()
    threads = []
    for env_idx in range(nenvs):
        th = Thread(target=run_env, args=(env, env_idx, args.action, nsteps, q))
        th.start()
        threads.append(th)
    for th in threads:
        th.join()