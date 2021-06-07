# directories

data_dir = 'data'
raw_dir = '{0}/raw'.format(data_dir)
spl_dir = '{0}/spl'.format(data_dir)
feature_dir = '{0}/features'.format(data_dir)
log_dir = 'logs'
vms_fpath = '{0}/vms.json'.format(log_dir)
ofports_fpath = '{0}/ofports.json'.format(log_dir)
nodes_fpath = '{0}/nodes.json'.format(log_dir)
actions_fpath = '{0}/actions.csv'.format(log_dir)
classfier_models_dir = 'models/classifiers'
classfier_results_dir = '{0}/results'.format(classfier_models_dir)
anomaly_detector_models_dir = 'models/anomaly_detectors'
anomaly_detector_results_dir = '{0}/results'.format(anomaly_detector_models_dir)
sources_dir = 'sources'
ovs_sources_dir = f'{sources_dir}/ovs/'
ids_sources_dir = f'{sources_dir}/ids/'
ads_sources_dir = f'{sources_dir}/ads/'
rl_models_dir = 'models'
rl_results_dir = 'results'
ids_model_weights_dir = '{0}/weights'.format(ids_sources_dir)
ads_model_weights_dir = '{0}/weights'.format(ads_sources_dir)
figures_dir = 'figures'
roc_dir = '{0}/roc'.format(figures_dir)
progress_dir = '{0}/progress'.format(figures_dir)

# vagrantfile

mgmt_network = '192.168.122.0/24'
env_vms = {
    'odl': {
        'unique': True,
        'n': 1,
        'cpus': 4,
        'ips': ['192.168.254.10'],
        'sources': [['./sources/opendaylight-0.12.3.tar.gz', 'opendaylight-0.12.3.tar.gz'], ['./sources/odl.service', '/home/vagrant/']],
        'script': 'scripts/odl.sh',
        'mount': None
    },
    'ovs': {
        'unique': False,
        'n': 1,
        'cpus': 3,
        'ips': ['192.168.254.20', '100.0.0.20'],
        'sources': [['./sources/ovs.service', '/home/vagrant/'], ['./sources/ovs', '/home/vagrant/']],
        'script': 'scripts/ovs.sh',
        'mount': ['./data/spl', '/home/vagrant/data/spl']
    },
    'ids': {
        'unique': False,
        'n': 1,
        'cpus': 2,
        'ips': ['192.168.254.60'],
        'sources': [['./sources/ids.service', '/home/vagrant/'], ['./sources/ids', '/home/vagrant/']],
        'script': 'scripts/ids.sh',
        'mount': None
    },
    'ads': {
        'unique': False,
        'n': 1,
        'cpus': 2,
        'ips': ['192.168.254.80'],
        'sources': [['./sources/ads.service', '/home/vagrant/'], ['./sources/ads', '/home/vagrant/']],
        'script': 'scripts/ads.sh',
        'mount': None
    }
}

# ids and ads

seed = 0
batch_size = 1024  # batch size will actually be double that
patience = 10
epochs = 100
steps_per_epoch = 1000
ds_params = ['nflows', 'delay']
n_ds_params = len(ds_params)
roc_fname = 'roc.csv'
fpr_levels = [0.01, 0.001, 0.0001]
fsize_min = 100000
som_nnn = 4

# sdn

ctrl_name = 'odl'
ctrl_port = 6653
in_table = 0
out_table = 10
block_table = out_table - 1
ids_tables = [idx for idx in range(1, block_table)]
priorities = {'lowest': 0, 'lower': 1, 'medium': 2, 'higher': 3, 'highest': 4}

# traffic

attackers = [
    '18.218.115.60',
    '18.219.9.1',
    '18.219.32.43',
    '18.218.55.126',
    '52.14.136.135',
    '18.219.5.43',
    '18.216.200.189',
    '18.218.229.235',
    '18.218.11.51',
    '18.216.24.42',
    '18.221.219.4',
    '13.58.98.64',
    '18.219.211.138',
    '18.217.165.70',
    '18.219.193.20',
    '13.58.225.34'
]

applications = [
    ('tcp', 21),
    ('tcp', 22),
    ('tcp', 23),
    ('udp', 53),
    ('tcp', 80),
    ('udp', 123),
    ('tcp', 443),
    ('tcp', 445),
    ('tcp', 3389),
    ('udp', 3389),
    ('tcp', ),
    ('udp', )
]

ip_proto_names = list(set([item[0] for item in applications]))
directions = ['source', 'destination']

# rl

precision_weight = 1
obs_stack_size = 4
train_attacks = [1, 2, 3, 4]
episode_duration = 32
nsteps = 64
nepisodes = 100000

# other

bridge_name = 'br'
traffic_generation_veth_prefix = 'in'
obs_bridge_veth_prefix = 'obs'
reward_bridge_veth_prefix = 'rew'
csv_postfix = '.csv'
aug_postfix = '_aug'
flask_port = 5000
flow_window = 1
