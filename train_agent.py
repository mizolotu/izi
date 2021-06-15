import argparse as arp
import os

from reinforcement_learning.gym.envs.reactive_discrete.main import ReactiveDiscreteEnv
from reinforcement_learning.ppo2.ppo2 import PPO2 as ppo
from reinforcement_learning.common.vec_env.subproc_vec_env import SubprocVecEnv
from reinforcement_learning.common.policies import MlpPolicy
from reinforcement_learning import logger
from reinforcement_learning.common.callbacks import CheckpointCallback
from config import *
from common.ml import load_meta
from itertools import cycle

def make_env(env_class, *args):
    fn = lambda: env_class(*args)
    return fn

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Train RL agent.')
    parser.add_argument('-s', '--scenario', help='Scenario name', default='intrusion_detection')
    parser.add_argument('-n', '--nenvs', help='Number of environments', type=int, default=nenvs)
    parser.add_argument('-a', '--attacks', help='Attack labels', nargs='+', default=train_attacks)
    parser.add_argument('-u', '--augment', help='Augment the data?', default=True, type=bool)
    parser.add_argument('-c', '--checkpoint', help='Checkpoint')  # e.g. 'rl_model_384_steps.zip'
    args = parser.parse_args()

    if args.nenvs is not None:
        nenvs = args.nenvs

    # handle attack indexes

    meta = load_meta(feature_dir)
    attack_labels = sorted([label for label in meta['labels'] if label > 0])
    attack_indexes = []
    for a in args.attacks:
        if a in attack_labels:
            idx = attack_labels.index(a)
            if idx not in attack_indexes:
                attack_indexes.append(idx)
    attack_indexes = cycle(attack_indexes)
    attack_str = ','.join([str(item) for item in args.attacks])

    # environment and algorithm

    env_class = ReactiveDiscreteEnv
    algorithm = ppo
    policy = MlpPolicy
    total_steps = nsteps * nepisodes

    # configure logger

    _dir = f'{env_class.__name__}/{algorithm.__name__}/{args.scenario}_{attack_str}'
    modeldir = f'{rl_models_dir}/{_dir}'
    logdir = f'{rl_results_dir}/{_dir}'
    format_strs = os.getenv('', 'stdout,log,csv').split(',')
    logger.configure(os.path.abspath(logdir), format_strs)

    # create environments

    env_fns = [make_env(env_class, env_idx, next(attack_indexes), args.augment) for env_idx in range(nenvs)]
    env = SubprocVecEnv(env_fns)

    # continue training

    try:
        model = algorithm.load('{0}/{1}'.format(modeldir, args.checkpoint))
        model.set_env(env)
        print('Model has been loaded from {0}!'.format(args.checkpoint))
    except Exception as e:
        print('Could not load the model, a new model will be created!')
        model = algorithm(policy, env, n_steps=nsteps, verbose=1)
    finally:
        cb = CheckpointCallback(nsteps, modeldir, verbose=1)
        model.learn(total_timesteps=total_steps, callback=cb)