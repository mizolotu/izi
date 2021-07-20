import argparse as arp
import os
import pandas as pd
import os.path as osp

from reinforcement_learning.gym.envs.reactive_discrete.main import ReactiveDiscreteEnv
from reinforcement_learning.ppo2.ppo2 import PPO2 as ppo2
from reinforcement_learning.ppoc.ppoc import PPOC as ppoc
from reinforcement_learning.acer.acer_simple import ACER as acer
from reinforcement_learning.acktr.acktr import ACKTR as acktr
from reinforcement_learning.common.vec_env.subproc_vec_env import SubprocVecEnv
from reinforcement_learning.common.policies import MlpPolicy
from reinforcement_learning import logger
from reinforcement_learning.common.callbacks import CheckpointCallback
from config import *
from common.ml import load_meta
from itertools import cycle

def find_checkpoint_with_max_step(checkpoint_dir, prefix='rl_model_'):
    checkpoint_files = [item for item in os.listdir(checkpoint_dir) if osp.isfile(osp.join(checkpoint_dir, item)) and item.startswith(prefix) and item.endswith('.zip')]
    spl = [item.split(prefix)[1] for item in checkpoint_files]
    checkpoint_step_numbers = [int(item.split('_steps.zip')[0]) for item in spl]
    idx = sorted(range(len(checkpoint_step_numbers)), key=lambda k: checkpoint_step_numbers[k])
    return checkpoint_files[idx[-1]]

def make_env(env_class, *args):
    fn = lambda: env_class(*args)
    return fn

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Train RL agent.')
    parser.add_argument('-e', '--environment', help='Environment name', default='ReactiveDiscreteEnv')
    parser.add_argument('-a', '--algorithm', help='Algorithm name', default='ppo2')
    parser.add_argument('-s', '--scenario', help='Scenario name', default='intrusion_detection')
    parser.add_argument('-n', '--nenvs', help='Number of environments', type=int, default=nenvs)
    parser.add_argument('-l', '--labels', help='Attack labels', nargs='+', type=int, default=train_attacks)
    parser.add_argument('-u', '--augment', help='Augment the data?', default=False, type=bool)
    parser.add_argument('-t', '--timestamp', help='Checkpoint timestamp', type=int)
    args = parser.parse_args()

    # number of environments

    if args.nenvs is not None:
        nenvs = args.nenvs

    # handle attack indexes

    meta = load_meta(feature_dir)
    attack_labels = sorted([label for label in meta['labels'] if label > 0])
    attack_indexes = []
    for a in args.labels:
        if a in attack_labels:
            idx = attack_labels.index(a)
            if idx not in attack_indexes:
                attack_indexes.append(idx)
    attack_indexes = cycle(attack_indexes)
    attack_str = ','.join([str(item) for item in args.labels])

    # environment and algorithm

    env_class = locals()[args.environment]
    algorithm = locals()[args.algorithm]
    policy = MlpPolicy
    total_steps = nsteps * nepisodes

    # dirs

    _dir = f'{env_class.__name__}/{algorithm.__name__}/{args.scenario}_{attack_str}'
    modeldir = f'{models_dir}/{_dir}'
    logdir = f'{results_dir}/{_dir}'
    format_strs = os.getenv('', 'stdout,log,csv').split(',')

    # create environments

    env_fns = [make_env(env_class, env_idx, next(attack_indexes), args.augment, env_idx) for env_idx in range(nenvs)]
    env = SubprocVecEnv(env_fns)

    try:

        # continue training

        if args.timestamp is None:
            checkpoint = find_checkpoint_with_max_step(modeldir)
        else:
            checkpoint = f'rl_model_{args.timestamp}_steps.zip'

        fname = osp.join(logdir, progress)
        p = pd.read_csv(fname, delimiter=',', dtype=float)
        logger.configure(os.path.abspath(logdir), format_strs)
        keys = p.keys()
        vals = p.values
        for i in range(vals.shape[0]):
            for j in range(len(keys)):
                logger.logkv(keys[j], vals[i, j])
            logger.dumpkvs()
        model = algorithm.load(osp.join(modeldir, checkpoint))
        model.set_env(env)
        print('Model has been loaded from {0}!'.format(checkpoint))
    except Exception as e:
        print(e)
        print('Could not load the model, a new model will be created!')
        logger.configure(os.path.abspath(logdir), format_strs)
        model = algorithm(policy, env, n_steps=nsteps, verbose=1)
    finally:
        cb = CheckpointCallback(nsteps * nenvs, modeldir, verbose=1)
        model.learn(total_timesteps=total_steps, callback=cb)