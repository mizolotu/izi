import argparse as arp
import json, os
import numpy as np

from reinforcement_learning.gym.envs.reactive1.main import AttackMitigationEnv
from reinforcement_learning.ppo2.ppo2 import PPO2 as ppo
from reinforcement_learning.common.vec_env.subproc_vec_env import SubprocVecEnv
from reinforcement_learning.common.policies import MlpPolicy
from reinforcement_learning import logger
from reinforcement_learning.common.callbacks import CheckpointCallback
from config import *

def make_env(env_class, *args):
    fn = lambda: env_class(*args)
    return fn

def test():
    env = AttackMitigationEnv(env_class, attack, nsteps)
    obs = env.reset()
    print(obs.shape)
    print(obs)
    print('Testing...')
    for i in range(env.n_hosts + 1):
        for j in range(env.n_apps + len(env.external_ports)):
            for k in range(env.n_dscp):
                for l in range(env.n_ids):
                    A = np.zeros((env.n_hosts + 1, env.n_apps + len(env.external_ports), env.n_dscp, env.n_ids))
                    A[i, j, k, l] = 1
                    A = A.reshape(np.prod(A.shape))
                    idx = np.where(A == 1)[0]
                    #print(idx, env._action_mapper(idx))
    n = (env.n_hosts + 1) * (env.n_apps + len(env.external_ports)) * env.n_dscp * env.n_ids
    for i in range(env.n_hosts + 1):
        for j in range(env.n_apps + len(env.external_ports)):
            for k in range(env.n_dscp):
                A = np.zeros((env.n_hosts + 1, env.n_apps + len(env.external_ports), env.n_dscp))
                A[i, j, k] = 1
                A = A.reshape(np.prod(A.shape))
                idx = n + np.where(A == 1)[0]
                #print(idx, env._action_mapper(idx))
    n = (env.n_hosts + 1) * (env.n_apps + len(env.external_ports)) * env.n_dscp * (env.n_ids + 1)
    for i in range(env.n_ids):
        for j in range(env.n_models):
            for k in range(env.n_thrs):
                A = np.zeros((env.n_ids, env.n_models, env.n_thrs))
                A[i, j, k] = 1
                A = A.reshape(np.prod(A.shape))
                idx = n + np.where(A == 1)[0]
                print(idx, env._action_mapper(idx))
                env._take_action(idx)

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Forward flow to IDS.')
    parser.add_argument('-a', '--attack', help='Attack', default=1, type=int, choices=[1, 2, 3, 4, 5, 6, 7, 8])
    parser.add_argument('-m', '--models', help='Output models', default='models/')
    parser.add_argument('-r', '--results', help='Output stats', default='results')
    parser.add_argument('-c', '--checkpoint', help='Checkpoint', default='')
    args = parser.parse_args()

    env_class = AttackMitigationEnv
    nenvs = 1
    algorithm = ppo
    policy = MlpPolicy
    total_steps = nsteps * nepisodes

    modeldir = '{0}/{1}/{2}/{3}'.format(args.models, env_class.__name__, algorithm.__name__, args.attack)
    logdir = '{0}/{1}/{2}/{3}'.format(args.results, env_class.__name__, algorithm.__name__, args.attack)
    format_strs = os.getenv('', 'stdout,log,csv').split(',')
    logger.configure(os.path.abspath(logdir), format_strs)

    env_fns = [make_env(env_class, args.attack, nsteps) for _ in range(nenvs)]
    env = SubprocVecEnv(env_fns)

    try:
        model = algorithm.load('{0}/{1}'.format(modeldir, args.checkpoint))
        model.set_env(env)
        print('Model has been loaded from {0}!'.format(args.checkpoint))
    except Exception as e:
        print('Could not load the model, new model will be created!')
        model = algorithm(policy, env, n_steps=nsteps, verbose=1)
    cb = CheckpointCallback(nsteps, modeldir, verbose=1)
    model.learn(total_timesteps=total_steps, callback=cb)
