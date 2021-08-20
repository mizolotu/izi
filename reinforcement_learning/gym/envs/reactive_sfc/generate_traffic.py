import os, pandas, requests, json
import os.path as osp
import numpy as np

from subprocess import Popen
from config import *
from common.ml import load_meta
from time import sleep
from pathlib import Path
from common.utils import isint

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

def select_file(profile, label):
    fnames = profile['fnames']
    probs = profile['probs'][:, label]
    idx = np.random.choice(np.arange(len(fnames)), p = probs)
    return fnames[idx]

def replay_pcap(fpath, iface):
    print('Replaying: {0}'.format(fpath))
    p = Popen(['tcpreplay', '-i', iface, '--duration', str(episode_duration), fpath]) #, stdout=DEVNULL, stderr=DEVNULL)
    return p

def set_seed(tgu_mgmt_ip, tgu_port, seed):
    url = 'http://{0}:{1}/seed'.format(tgu_mgmt_ip, tgu_port)
    requests.post(url, json={'seed': seed})

def prepare_traffic_on_interface(ovs_ip, ovs_port, ips, label_idx, duration):
    url = 'http://{0}:{1}/prepare'.format(ovs_ip, ovs_port)
    requests.post(url, json={'ips': ips, 'label': label_idx, 'duration': duration})

def replay_traffic_on_interface(ovs_ip, ovs_port, duration):
    url = 'http://{0}:{1}/replay'.format(ovs_ip, ovs_port)
    requests.post(url, json={'duration': duration})

def replay_ip_traffic_on_interface(ovs_ip, ovs_port, ip, fname, label, duration):
    url = 'http://{0}:{1}/replay'.format(ovs_ip, ovs_port)
    r = requests.post(url, json={'ip': ip, 'fname': fname, 'label': label, 'duration': duration})
    return r.json()

if __name__ == '__main__':

    meta = load_meta(data_dir)
    labels = meta['labels']
    env_idx = 0
    label = 4
    profiles = calculate_probs(stats_dir, labels)

    with open(vms_fpath, 'r') as f:
        vms = json.load(f)
    ovs_vms = [vm for vm in vms if vm['role'] == 'ovs' and int(vm['vm'].split('_')[1]) == env_idx]
    assert len(ovs_vms) == 1
    ovs_vm = ovs_vms[0]

    ips = sorted([item for item in os.listdir(spl_dir) if osp.isdir(osp.join(spl_dir, item))])
    for ip in ips:
        if ip in profiles[label].keys():
        else:
        profile = profiles[label][ip]
        probs = profile[1]
        idx = np.random.choice(np.arange(len(probs)), p=probs)
        fname = profile[0][idx]
        replay_ip_traffic_on_interface(ovs_vm['mgmt'], flask_port, ip, fname, label, episode_duration)
    sleep(episode_duration)
    print('Done!')