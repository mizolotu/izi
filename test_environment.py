import argparse as arp

from config import *
from common.ml import load_meta
from common import data
from reinforcement_learning.gym.envs.reactive_sfc.main import ReactiveDiscreteEnv

def make_env(env_class, *args):
    fn = lambda: env_class(*args)
    return fn

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Test environment.')
    parser.add_argument('-e', '--environment', help='Environment name', default='ReactiveDiscreteEnv')
    parser.add_argument('-l', '--labels', help='Attack labels', nargs='+', type=int, default=train_attacks)
    parser.add_argument('-r', '--labeler', help='Reverse labeler', default='reverse_label_cicids')
    args = parser.parse_args()

    reverse_labeler = getattr(data, args.labeler)
    meta = load_meta(data_dir)
    attack_labels = sorted([label for label in meta['labels'] if label > 0])
    attacks = []
    attack_data = {}
    for a in args.labels:
        if a in attack_labels and a not in attacks:
            attacks.append(a)
            attack_ips, attack_directions = reverse_labeler(a)
            attack_data[a] = (attack_ips, attack_directions)
    attack_str = ','.join([str(item) for item in attacks])

    env_class = locals()[args.environment]
    default_policy = {'reset': [], 'step': []}
    env = env_class(0, attacks, attack_data, False, seed, default_policy, debug=True)
    env.reset()



