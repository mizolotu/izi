traffic_generation_iface = 'virbr2'  # change this to the name of the interface which has ip 10.0.0.1
meta_dir = 'data/features'
samples_dir = 'data/spl'
vms_fpath = 'logs/vms.json'
tunnels_fpath = 'logs/tunnels.json'
nodes_fpath = 'logs/nodes.json'
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
ids_tables = [idx for idx in range(2, ntables - 1)]
block_table = 8
priorities = {'low': 0, 'medium': 1, 'high': 2}
ip_proto = 2048
csv_postfix = '.csv'
episode_duration = 32
nsteps = 128
nepisodes = 100000
ids_model_weights_dir = 'sources/ids/weights'
ids_port = 5000
ids_params = ['nflows', 'delay']
n_ids_params = len(ids_params)