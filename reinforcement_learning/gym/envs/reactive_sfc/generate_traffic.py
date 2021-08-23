import os, pandas, requests, json
import os.path as osp
import numpy as np
import argparse as arp

from config import *
from common.ml import load_meta
from time import sleep
from common import data

def calculate_probs(samples_dir, labels, criteria='flows'):
    label_dirs = []
    labels_selected = []
    for label in labels:
        if osp.isdir(osp.join(samples_dir, str(label))):
            label_dirs.append(osp.join(samples_dir, str(label)))
            labels_selected.append(label)
    profiles = {}
    for label, label_dir in zip(labels_selected, label_dirs):
        profiles[label] = {}
        for stats_file in os.listdir(label_dir):
            fpath = osp.join(label_dir, stats_file)
            vals = pandas.read_csv(fpath, header=None).values
            idx = np.where(vals[:, 2] >= npkts_min)[0]
            assert len(idx) > 0
            fnames = vals[idx, 0]
            if criteria == 'flows':
                probs = vals[idx, 1] / np.sum(vals[idx, 1])
            elif criteria == 'packets':
                probs = vals[idx, 2] / np.sum(vals[idx, 2])
            profiles[label][stats_file] = [fnames, probs.astype(dtype=float)]
    return profiles

def set_seed(tgu_mgmt_ip, tgu_port, seed):
    url = 'http://{0}:{1}/seed'.format(tgu_mgmt_ip, tgu_port)
    requests.post(url, json={'seed': seed})

def prepare_traffic_on_interface(ovs_ip, ovs_port, fname, augment=False):
    url = 'http://{0}:{1}/readpcap'.format(ovs_ip, ovs_port)
    r = requests.post(url, json={'ip': ip, 'fname': fname, 'augment': augment})
    return r.json()

def replay_traffic_on_interface(ovs_ip, ovs_port, duration):
    url = 'http://{0}:{1}/replay'.format(ovs_ip, ovs_port)
    r = requests.post(url, json={'duration': duration})
    return r.json()

if __name__ == '__main__':

    # process args

    parser = arp.ArgumentParser(description='Generate datasets')
    parser.add_argument('-l', '--labeler', help='Labeler', default='reverse_label_cicids17_short')
    args = parser.parse_args()

    # import labeler

    reverse_labeler = getattr(data, args.labeler)

    # meta

    meta = load_meta(data_dir)
    labels = meta['labels']
    env_idx = 0
    label = 4
    profiles = calculate_probs(stats_dir, labels)
    augment = True

    # vms

    with open(vms_fpath, 'r') as f:
        vms = json.load(f)
    ovs_vms = [vm for vm in vms if vm['role'] == 'ovs' and int(vm['vm'].split('_')[1]) == env_idx]
    assert len(ovs_vms) == 1
    ovs_vm = ovs_vms[0]

    # prepare traffic

    aug_ips, aug_directions = reverse_labeler(label)
    ips = sorted([item for item in os.listdir(spl_dir) if osp.isdir(osp.join(spl_dir, item))])
    for ip in ips:
        if ip in profiles[label].keys():
            prob_idx = label
            if augment:
                aug = {'ips': aug_ips, 'directions': aug_directions}
            else:
                aug = None
        else:
            prob_idx = 0
            aug = None
        fname_idx = np.random.choice(np.arange(len(profiles[prob_idx][ip][1])), p=profiles[prob_idx][ip][1])
        fnames = [f'{profiles[prob_idx][ip][0][fname_idx]}_label:{prob_idx}']
        augments = [aug]
        if prob_idx > 0:
            fnames.append(f'{profiles[prob_idx][ip][0][fname_idx]}_label:{0}')
            augments.append(None)
        for fname, aug in zip(fnames, augments):
            prepare_traffic_on_interface(ovs_vm['mgmt'], flask_port, fname, augment=aug)

    # replay

    replay_traffic_on_interface(ovs_vm['mgmt'], flask_port, episode_duration)

    sleep(episode_duration)
    print('Done!')