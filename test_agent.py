import argparse as arp
import os

from reinforcement_learning.gym.envs.reactive1.main import AttackMitigationEnv
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

    parser = arp.ArgumentParser(description='Test agent.')
    parser.add_argument('-c', '--checkpoint', help='Checkpoint')
    parser.add_argument('-a', '--attack', help='Attack index', default=0)
    args = parser.parse_args()

    env_class = AttackMitigationEnv
    algorithm = ppo
    policy = MlpPolicy
    modeldir = '{0}/{1}/{2}'.format(rl_models_dir, env_class.__name__, algorithm.__name__)

    try:
        model = algorithm.load('{0}/{1}'.format(modeldir, args.checkpoint))
        env_fns = [make_env(env_class, 0, int(args.attack))]
        env = SubprocVecEnv(env_fns)
        model.set_env(env)
        print('Model has been loaded from {0}!'.format(args.checkpoint))
    except Exception as e:
        print('Could not load the model, a new model will be created!')
        model = algorithm(policy, env, n_steps=nsteps, verbose=1)
    finally:
        model.demo()



