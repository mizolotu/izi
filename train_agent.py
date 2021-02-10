import argparse as arp
import json, os
import numpy as np

from reinforcement_learning.gym.envs.attack_mitigation_env import AttackMitigationEnv
from reinforcement_learning.ppo2.ppo2 import PPO2 as ppo
from reinforcement_learning.common.vec_env.subproc_vec_env import SubprocVecEnv
from reinforcement_learning.common.policies import MlpPolicy
from reinforcement_learning import logger
from reinforcement_learning.common.callbacks import CheckpointCallback

def make_env(env_class, *args):
    fn = lambda: env_class(*args)
    return fn

def test():
    env = AttackMitigationEnv(vms, tunnels, nodes, containers, scenario)
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
    parser.add_argument('-m', '--models', help='Output models', default='models/')
    parser.add_argument('-l', '--loadsteps', help='Load steps', default='256')
    parser.add_argument('-r', '--results', help='Output stats', default='results')
    parser.add_argument('-p', '--postfix', help='Output postfix', default='part1')
    parser.add_argument('-v', '--vms', help='File with vms', default='logs/vms.json')
    parser.add_argument('-t', '--tunnels', help='File with tunnels', default='logs/tunnels.json')
    parser.add_argument('-c', '--containers', help='File with containers', default='logs/containers.json')
    parser.add_argument('-n', '--nodes', help='File with nodes', default='logs/nodes.json')
    parser.add_argument('-s', '--scenario', help='File with traffic scenario', default='scenarios/traffic/test1.json')
    args = parser.parse_args()

    with open(args.vms, 'r') as f:
        vms = json.load(f)

    with open(args.nodes, 'r') as f:
        nodes = json.load(f)

    with open(args.tunnels, 'r') as f:
        tunnels = json.load(f)

    with open(args.containers, 'r') as f:
        containers = json.load(f)

    with open(args.scenario, 'r') as f:
        scenario = json.load(f)

    env_class = AttackMitigationEnv
    nenvs = 1
    algorithm = ppo
    policy = MlpPolicy
    nsteps = 256*10000

    modeldir = '{0}/{1}_{2}_{3}'.format(args.models, env_class.__name__, algorithm.__name__, policy.__name__)
    logdir = '{0}/{1}/{2}/{3}/{4}/'.format(args.results, env_class.__name__, algorithm.__name__, policy.__name__, args.postfix)
    format_strs = os.getenv('', 'stdout,log,csv').split(',')
    logger.configure(os.path.abspath(logdir), format_strs)

    env_fns = [make_env(env_class, vms, tunnels, nodes, containers, scenario) for _ in range(nenvs)]
    env = SubprocVecEnv(env_fns)

    model = algorithm(policy, env, verbose=1)
    try:
        model.load('{0}/rl_model_{1}_steps.zip'.format(modeldir, args.loadsteps), env)
    except Exception as e:
        print(e)
    cb = CheckpointCallback(256, modeldir, verbose=1)
    model.learn(total_timesteps=nsteps, callback=cb)
