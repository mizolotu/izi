from reinforcement_learning.gym.envs.classic_control.cartpole import CartPoleEnv
from reinforcement_learning.common.vec_env import SubprocVecEnv
from reinforcement_learning.common.policies import MlpPolicyDefault as policy
from reinforcement_learning.ppo2.ppo2 import PPO2 as ppo
from reinforcement_learning.acktr.acktr import ACKTR as acktr
from reinforcement_learning.acer.acer_simple import ACER as acer

def make_env(env_class):
    fn = lambda: env_class()
    return fn

if __name__ == '__main__':

    nenvs = 4
    nsteps = nenvs * int(1e6)

    env_fns = [make_env(CartPoleEnv) for _ in range(nenvs)]
    env = SubprocVecEnv(env_fns)

    #model = ppo(ppo_policy, env, verbose=1)
    model = acktr(policy, env, verbose=1)
    #model = acer(policy, env, verbose=1)
    model.learn(total_timesteps=nsteps)