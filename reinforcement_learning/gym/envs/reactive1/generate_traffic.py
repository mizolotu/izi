import os, pandas, requests, json
import os.path as osp
import numpy as np

from subprocess import Popen
from config import *
from common.ml import load_meta
from time import sleep
from pathlib import Path

def calculate_probs(samples_dir, fsize_min=100000):
    profile_files = sorted([osp.join(samples_dir, item) for item in os.listdir(samples_dir) if osp.isfile(osp.join(samples_dir, item)) and item.endswith(csv_postfix)])
    profiles = []
    for profile_file in profile_files:
        vals = pandas.read_csv(profile_file, header=None).values
        fnames = vals[:, 0]
        fsizes = np.array([Path(f).stat().st_size for f in fnames])
        freqs = vals[:, 1:]
        freqs0 = vals[:, 1]
        probs = np.zeros_like(freqs, dtype=float)
        nlabels = freqs.shape[1]
        for i in range(nlabels):
            s = np.sum(freqs[:, i])
            if s == 0:
                probs1 = np.sum(freqs[:, 1:], axis=1)  # sum of frequencies of files with malicious traffic
                idx0 = np.where((probs1 == 0) & (fsizes > fsize_min))[0]  # index of files with no malicious traffic
                counts0 = np.zeros_like(freqs0)
                counts0[idx0] = freqs0[idx0]
                s0 = np.sum(counts0)
                probs[:, i] = counts0 / s0
            else:
                idx1 = np.where(fsizes > fsize_min)[0]
                if len(idx1) > 0:
                    counts1 = np.zeros_like(freqs[:, i])
                    counts1[idx1] = freqs[idx1, i]
                    s1 = np.sum(counts1)
                    probs[:, i] = counts1 / s1
                else:
                    s1 = np.sum(freqs[:, i])
                    probs[:, i] = freqs[:, i] / s1
        profiles.append({'fpath': profile_file, 'fnames': fnames, 'probs': probs})
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

def set_seed(tgu_mgmt_ip, seed):
    url = 'http://{0}:{1}/seed'.format(tgu_mgmt_ip, ids_port)
    requests.post(url, json={'seed': seed})

def generate_ip_traffic_on_interface(tgu_mgmt_ip, veth_idx, ip, label_idx, duration):
    url = 'http://{0}:{1}/replay'.format(tgu_mgmt_ip, ids_port)
    requests.post(url, json={'ip': ip, 'idx': veth_idx, 'label': label_idx, 'duration': duration})

if __name__ == '__main__':

    meta = load_meta(feature_dir)
    labels = meta['labels']
    env_idx = 0
    label = 3
    label_idx = labels.index(label)
    ip = '172.31.69.28'

    with open(vms_fpath, 'r') as f:
        vms = json.load(f)
    tgu_vms = [vm for vm in vms if vm['vm'].startswith('tgu')]
    assert len(tgu_vms) == 1
    tgu_vm = tgu_vms[0]

    generate_ip_traffic_on_interface(tgu_vm['mgmt'], env_idx, ip, label_idx, episode_duration)
    sleep(episode_duration)
    print('Passed!')