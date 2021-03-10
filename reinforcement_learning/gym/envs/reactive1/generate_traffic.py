import os, pandas
import os.path as osp
import numpy as np

from subprocess import Popen, DEVNULL
from config import *
from common.ml import load_meta
from time import sleep
from pathlib import Path

def calculate_probs(samples_dir, postfix='.csv'):
    profile_files = sorted([osp.join(samples_dir, item) for item in os.listdir(samples_dir) if osp.isfile(osp.join(samples_dir, item)) and item.endswith(postfix)])
    profiles = []
    for profile_file in profile_files:
        vals = pandas.read_csv(profile_file, header=None).values
        fnames = vals[:, 0]
        fsizes = np.array([Path(f).stat().st_size for f in fnames])
        freqs = vals[:, 1:]
        probs = np.zeros_like(freqs, dtype=float)
        nfiles = freqs.shape[0]
        nlabels = freqs.shape[1]
        for i in range(nlabels):
            s1 = np.sum(freqs[:, i])
            s2 = np.sum(fsizes)
            if s1 == 0:
                probs[:, i] = fsizes / s2
            else:
                probs[:, i] = freqs[:, i] / s1
        profiles.append({'fpath': profile_file, 'fnames': fnames, 'probs': probs})
    return profiles

def select_file(profile, label):
    fnames = profile['fnames']
    probs = profile['probs'][:, label]
    idx = np.random.choice(np.arange(len(fnames)), p = probs)
    return fnames[idx]

def replay_pcap(fpath, iface):
    p = Popen(['tcpreplay', '-i', iface, '--duration', str(episode_duration), fpath], stdout=DEVNULL, stderr=DEVNULL)
    return p

if __name__ == '__main__':

    meta = load_meta(meta_dir)
    labels = np.array(meta['labels'])
    mlabels = labels[labels > 0]
    label = 6 # np.random.choice(mlabels)

    # load profiles

    profiles = calculate_probs(samples_dir)

    # sample files

    prcs = []
    for p in profiles:
        print(p['probs'].shape)
        fpath = select_file(p, label)
        print(fpath)
        po = replay_pcap(fpath, traffic_generation_iface)
        prcs.append(po)

    while True:
        print('here')
        sleep(1)

    print('Passed!')