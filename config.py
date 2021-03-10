data_dir = 'data'
raw_dir = '{0}/raw'.format(data_dir)
spl_dir = '{0}/spl'.format(data_dir)
feature_dir = '{0}/features'.format(data_dir)
log_dir = 'logs'
vms_fpath = '{0}/vms.json'.format(log_dir)
tunnels_fpath = '{0}/tunnels.json'.format(log_dir)
nodes_fpath = '{0}/nodes.json'.format(log_dir)
classfier_models_dir = 'models/classifiers'
ids_sources_dir = 'sources/ids/'
fpr_levels = [0.01, 0.0001, 0.000001]
ctrl_name = 'odl'
traffic_generation_ifaces = ['virbr4', 'virbr2', 'virbr3']  # change these to the names of the interfaces which have ips 100.0.0.1, 101.0.0.1, etc
meta_dir = 'data/features'
samples_dir = 'data/spl'
rl_models_dir = 'models'
rl_results_dir = 'results'
ntables = 10
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
    ('udp', 3389)
]
ip_proto_names = list(set([item[0] for item in applications]))
directions = ['source', 'destination']
app_table = 0
reward_tables = [1, ntables - 1]
ids_tables = [idx for idx in range(2, ntables - 2)]
block_table = ntables - 1
priorities = {'low': 0, 'medium': 1, 'high': 2}
ip_proto = 2048
csv_postfix = '.csv'
episode_duration = 32
nsteps = 128
nepisodes = 100000
ids_model_weights_dir = '{0}/weights'.format(ids_sources_dir)
ids_port = 5000
ids_params = ['nflows', 'delay']
n_ids_params = len(ids_params)