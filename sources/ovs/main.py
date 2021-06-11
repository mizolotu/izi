import json, logging, pcap, pandas, os
import numpy as np
import os.path as osp

from subprocess import Popen, DEVNULL
from pathlib import Path
from collections import deque
from threading import Thread
from flask import Flask, request, jsonify
from datetime import datetime
from common.data import read_pkt
from time import sleep

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

@app.route('/seed', methods=['GET', 'POST'])
def seed():
    global seed
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        seed = jdata['seed']
        np.random.seed(seed)
    return jsonify(seed)

@app.route('/replay', methods=['GET', 'POST'])
def prepare():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        label = jdata['label']
        ip = jdata['ip']
        duration = jdata['duration']
        aug = jdata['aug']
        ipidx = ips.index(ip)
        profile = profiles[ipidx]
        fpath = select_file(profile, label, aug)
        replay_pcap(fpath, iface, duration)
    return jsonify(fpath)

def calculate_probs(samples_dir, fsize_min=100000):
    ready = False
    while not ready:
        try:
            profile_files = sorted([item for item in os.listdir(samples_dir) if osp.isfile(osp.join(samples_dir, item)) and item.endswith('.csv')])
            profiles = []
            ips = []
            for profile_file in profile_files:
                ip = profile_file.split('.csv')[0]
                fpath = osp.join(samples_dir, profile_file)
                vals = pandas.read_csv(fpath, header=None).values
                fnames = vals[:, 0]
                fsizes = np.array([Path(osp.join(home_dir, f)).stat().st_size for f in fnames])
                freqs = vals[:, 1:]
                freqs0 = freqs[:, 0]
                freqs1 = freqs[:, 1:]
                probs = np.zeros_like(freqs1, dtype=float)
                nlabels = freqs1.shape[1]
                for i in range(nlabels):
                    s = np.sum(freqs1[:, i])
                    if s == 0:
                        probs1 = np.sum(freqs1, axis=1)  # sum of frequencies of files with malicious traffic
                        idx0 = np.where((probs1 == 0) & (fsizes > fsize_min))[0]  # index of files with no malicious traffic
                        counts0 = np.zeros_like(freqs0)
                        counts0[idx0] = freqs0[idx0]
                        s0 = np.sum(counts0)
                        probs[:, i] = counts0 / s0
                    else:
                        idx1 = np.where(fsizes > fsize_min)[0]
                        if len(idx1) > 0:
                            counts1 = np.zeros_like(freqs1[:, i])
                            counts1[idx1] = freqs1[idx1, i]
                            s1 = np.sum(counts1)
                            probs[:, i] = counts1 / s1
                        else:
                            s1 = np.sum(freqs1[:, i])
                            probs[:, i] = freqs1[:, i] / s1

                profiles.append({'fpath': fpath, 'fnames': fnames, 'probs': probs})
                ips.append(ip)
            ready = True
        except Exception as e:
            print(e)
            sleep(1)
    return ips, profiles

def select_file(profile, label, aug=True):
    fnames = profile['fnames']
    probs = profile['probs'][:, label]
    idx = np.random.choice(np.arange(len(fnames)), p = probs)
    if aug and osp.isfile(osp.join(home_dir, f'{fnames[idx]}_aug')):
        fpath = osp.join(home_dir, f'{fnames[idx]}_aug')
    else:
        fpath = osp.join(home_dir, fnames[idx])
    return fpath

def replay_pcap(fpath, iface, duration):
    Popen(['tcpreplay', '-i', iface, '--duration', str(duration), fpath], stdout=DEVNULL, stderr=DEVNULL)

@app.route('/samples')
def samples():
    data = request.data.decode('utf-8')
    jdata = json.loads(data)
    vals = flow_collector.retrieve_data(jdata['window'])
    return jsonify(vals)

@app.route('/report')
def report():
    in_pkts = [[ts, *read_pkt(pkt)] for ts, pkt in list(flow_collector.in_pkts)]
    out_pkts = [[ts, *read_pkt(pkt)] for ts, pkt in list(flow_collector.out_pkts)]
    return jsonify({'in_pkts': in_pkts, 'out_pkts': out_pkts, 'timestamps': list(flow_collector.state_timestamps)})

@app.route('/reset')
def reset():
    flow_collector.clear_queues()
    return jsonify('ok')

class FlowCollector():

    def __init__(self, in_iface='obs_br', out_iface='rew_br'):
        self.in_iface = in_iface
        self.out_iface = out_iface
        self.in_pkts = deque()
        self.out_pkts = deque()
        self.state_timestamps = deque()

    def start(self):
        in_thr = Thread(target=self._recv, args=(self.in_iface, self.in_pkts), daemon=True)
        in_thr.start()
        out_thr = Thread(target=self._recv, args=(self.out_iface, self.out_pkts), daemon=True)
        out_thr.start()

    def _recv(self, iface, dq):
        ready = False
        while not ready:
            try:
                sniffer = pcap.pcap(name=iface)
                ready = True
                while True:
                    ts, raw = next(sniffer)
                    dq.appendleft((ts, raw))
            except Exception as e:
                print(e)

    def retrieve_data(self, window):
        tnow = datetime.now().timestamp()
        self.state_timestamps.appendleft(tnow)
        in_items = list(self.in_pkts)
        samples = []
        for item in in_items:
            if item[0] > tnow - window:
                samples.append(read_pkt(item[1]))
            else:
                break
        return samples

    def clear_queues(self):
        self.in_pkts.clear()
        self.out_pkts.clear()
        self.state_timestamps.clear()

if __name__ == '__main__':

    iface = 'in_br'
    home_dir = '/home/vagrant'
    data_dir = f'{home_dir}/data/spl'
    episode_raw_dir = f'{home_dir}/episode_raw'
    episode_mod_dir = f'{home_dir}/episode_mod'
    if not osp.isdir(episode_raw_dir):
        os.mkdir(episode_raw_dir)
    if not osp.isdir(episode_mod_dir):
        os.mkdir(episode_mod_dir)

    ips, profiles = calculate_probs(data_dir)
    seed = None

    flow_collector = FlowCollector()
    flow_collector.start()

    app.run(host='0.0.0.0')