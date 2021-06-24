import os
import argparse as arp
import numpy as np
import pandas as pd
import os.path as osp

from reinforcement_learning.gym.envs.reactive_discrete.main import ReactiveDiscreteEnv
from reinforcement_learning.ppo2.ppo2 import PPO2 as ppo
from reinforcement_learning.common.vec_env.subproc_vec_env import SubprocVecEnv
from reinforcement_learning.common.policies import MlpPolicy
from config import *
from common.ml import load_meta

def make_env(env_class, *args):
    fn = lambda: env_class(*args)
    return fn

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Test agent.')
    parser.add_argument('-e', '--environment', help='Environment name', default='ReactiveDiscreteEnv')
    parser.add_argument('-i', '--id', help='Environment id', default=0, type=int)
    parser.add_argument('-a', '--algorithm', help='Algorithm name', default='ppo')
    parser.add_argument('-c', '--checkpoint', help='Checkpoint')  # e.g. 'rl_model_384_steps.zip'
    parser.add_argument('-s', '--scenario', help='Scenario name', default='intrusion_detection')
    parser.add_argument('-r', '--reset', help='Default reset actions',nargs='+', type=int, default=[4, 48, 54, 58]) # 0,1,2,3,4,5,6,7,8,9,10,11,50,54,58
    parser.add_argument('-t', '--step', help='Default step actions',nargs='+', type=int, default=[28]) # 24,25,26,27,28,29,30,31,32,33,34,35
    parser.add_argument('-l', '--labels', help='Attack labels', nargs='+', type=int, default=train_attacks)
    parser.add_argument('-d', '--ntests', help='Number of tests', default=ntests, type=int)
    parser.add_argument('-u', '--augment', help='Augment the data?', default=False, type=bool)
    parser.add_argument('-p', '--prefix', help='Prefix')
    parser.add_argument('-n', '--nenvs', help='Number of environments', default=nenvs, type=int)
    args = parser.parse_args()

    # handle attack indexes

    meta = load_meta(feature_dir)
    attack_labels = sorted([label for label in meta['labels'] if label > 0])
    attack_indexes = []
    for a in args.labels:
        if a in attack_labels:
            idx = attack_labels.index(a)
            if idx not in attack_indexes:
                attack_indexes.append(idx)
    attack_str = ','.join([str(item) for item in args.labels])
    env_class = locals()[args.environment]
    algorithm = locals()[args.algorithm]
    modeldir = f'{models_dir}/{env_class.__name__}/{algorithm.__name__}/{args.scenario}_{attack_str}'
    policy = MlpPolicy

    try:
        model = algorithm.load('{0}/{1}'.format(modeldir, args.checkpoint))
        env_fns = [make_env(env_class, 0, int(args.attack), args.augment, args.seed)]
        env = SubprocVecEnv(env_fns)
        model.set_env(env)
        print('Model has been loaded from {0}!'.format(args.checkpoint))
    except Exception as e:
        default_policy = {'reset': args.reset, 'step': args.step}
        print(f'Static policy to be executed: {default_policy}')
        env_fns = [make_env(env_class, 0, attack_indexes, args.augment, seed, default_policy)]
        env = SubprocVecEnv(env_fns)
        model = algorithm(policy, env, n_steps=nsteps, verbose=1)
    finally:
        r, n, a, p = model.demo(args.ntests)

    # save the result as baseline for default policy

    if args.prefix is not None:
        env_dir = osp.join(results_dir, env_class.__name__)
        _dir = osp.join(env_dir, args.prefix)
        _scenario_dir = osp.join(_dir, f'{args.scenario}_{attack_str}')
        for d in [env_dir, _dir, _scenario_dir]:
            if not osp.isdir(d):
                os.mkdir(d)
        fpath = osp.join(_scenario_dir, progress)
        p = pd.DataFrame({
            'ep_reward_mean': r,
            'ep_normal_mean': n,
            'ep_attack_mean': a,
            'ep_precision_mean': p,
            'total_timesteps': [i * args.nenvs * nsteps for i in range(1, args.ntests + 1)]
        })
        p.to_csv(fpath, index=False)