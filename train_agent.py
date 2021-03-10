import argparse as arp
import os

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

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Forward flow to IDS.')
    parser.add_argument('-a', '--attack', help='Attack', default=1, type=int, choices=[1, 2, 3, 4, 5, 6, 7, 8])
    parser.add_argument('-c', '--checkpoint', help='Checkpoint', default='')
    args = parser.parse_args()

    env_class = AttackMitigationEnv
    nenvs = 3
    algorithm = ppo
    policy = MlpPolicy
    total_steps = nsteps * nepisodes

    modeldir = '{0}/{1}/{2}/{3}'.format(rl_models_dir, env_class.__name__, algorithm.__name__, args.attack)
    logdir = '{0}/{1}/{2}/{3}'.format(rl_results_dir, env_class.__name__, algorithm.__name__, args.attack)
    format_strs = os.getenv('', 'stdout,log,csv').split(',')
    logger.configure(os.path.abspath(logdir), format_strs)

    env_fns = [make_env(env_class, env_idx, args.attack, nsteps) for env_idx in range(nenvs)]
    env = SubprocVecEnv(env_fns)

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