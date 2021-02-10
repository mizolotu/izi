import os

from reinforcement_learning.a2c import A2C
from reinforcement_learning.acktr import ACKTR
from reinforcement_learning.ppo2 import PPO2

# Load mpi4py-dependent algorithms only if mpi is installed.
try:
    import mpi4py
except ImportError:
    mpi4py = None

if mpi4py is not None:
    from reinforcement_learning.ddpg import DDPG
    from reinforcement_learning.gail import GAIL
    from reinforcement_learning.ppo1 import PPO1
    from reinforcement_learning.trpo_mpi import TRPO
del mpi4py

# Read version from file
version_file = os.path.join(os.path.dirname(__file__), 'version.txt')
with open(version_file, 'r') as file_handler:
    __version__ = file_handler.read().strip()
