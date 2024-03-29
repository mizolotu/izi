from reinforcement_learning.gym.envs.classic_control.cartpole import CartPoleEnv
from reinforcement_learning.gym.envs.box2d.lunar_lander import LunarLander
from reinforcement_learning.common.vec_env import SubprocVecEnv
from reinforcement_learning.common.policies import MlpPolicy, ICMPolicy
from reinforcement_learning.ppoc.ppoc import PPOC as ppo_c
from reinforcement_learning.ppo2.ppo2 import PPO2 as ppo
from reinforcement_learning.acktr.acktr import ACKTR as acktr
from reinforcement_learning.acer.acer_simple import ACER as acer
from reinforcement_learning.common.misc_util import set_global_seeds

def make_env(env_class, seed):
    fn = lambda: env_class(seed)
    return fn

if __name__ == '__main__':

    env_class = LunarLander
    #env_class = CartPoleEnv
    nenvs = 4
    nsteps = nenvs * int(1e3)

    set_global_seeds(seed=0)
    env_fns = [make_env(env_class, seed) for seed in range(nenvs)]
    env = SubprocVecEnv(env_fns)

    model = ppo(MlpPolicy, env, n_steps=512, seed=0, verbose=1)
    model.learn(total_timesteps=nsteps)
    model.save('/tmp/model.zip')

    #model = ppo_c(MlpPolicy, env, n_steps=512, seed=0, verbose=1)
    #model = acktr(MlpPolicy, env, verbose=1)
    #model = acer(MlpPolicy, env, verbose=1)