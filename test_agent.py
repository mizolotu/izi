import argparse as arp
import sys

from reinforcement_learning.gym.envs.reactive1.main import AttackMitigationEnv
from reinforcement_learning.ppo2.ppo2 import PPO2 as ppo
from reinforcement_learning.common.vec_env.subproc_vec_env import SubprocVecEnv
from reinforcement_learning.common.policies import MlpPolicy
from config import *

def make_env(env_class, *args):
    fn = lambda: env_class(*args)
    return fn

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Test agent.')
    parser.add_argument('-c', '--checkpoint', help='Checkpoint')  # e.g. 'rl_model_384_steps.zip'
    parser.add_argument('-p', '--policy', help='Policy', default='0,1,2,3,4,5,6,7,8,9,10,11,54;24,25,26,27,28,29,30,31,32,33,34,35')
    parser.add_argument('-a', '--attack', help='Attack index', default=0)
    parser.add_argument('-n', '--ntests', help='Number of tests', default=10)
    args = parser.parse_args()

    if args.checkpoint is not None and args.policy is not None:
        print('Please specify only one of the following: rl model checkpoint or your manual security policy')
        sys.exit(1)

    if args.checkpoint is None and args.policy is None:
        print('Please specify at least one of the following: rl model checkpoint or your manual security policy')
        sys.exit(1)

    env_class = AttackMitigationEnv
    algorithm = ppo
    modeldir = '{0}/{1}/{2}'.format(rl_models_dir, env_class.__name__, algorithm.__name__)
    policy = MlpPolicy
    seed = 0

    try:
        model = algorithm.load('{0}/{1}'.format(modeldir, args.checkpoint))
        env_fns = [make_env(env_class, 0, int(args.attack), seed)]
        env = SubprocVecEnv(env_fns)
        model.set_env(env)
        print('Model has been loaded from {0}!'.format(args.checkpoint))
    except Exception as e:
        spl = args.policy.split(';')
        assert len(spl) == 2
        default_policy = {'reset': [int(item) for item in spl[0].split(',')], 'step': [int(item) for item in spl[1].split(',')]}
        print(default_policy)
        env_fns = [make_env(env_class, 0, int(args.attack), seed, default_policy)]
        env = SubprocVecEnv(env_fns)
        model = algorithm(policy, env, n_steps=nsteps, verbose=1)
        print('Could not load the model, using the default policy specified!')
    finally:
        model.demo(args.ntests)



