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
def replay():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        duration = jdata['duration']
        label = jdata['label']
        ip = jdata['ip']
        iface = 'in_br'
        ipidx = ips.index(ip)
        profile = profiles[ipidx]
        fpath = select_file(profile, label)
        replay_pcap(fpath, iface, duration)
    return jsonify('ok')

def calculate_probs(samples_dir, fsize_min=100000):
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
        profiles.append({'fpath': fpath, 'fnames': fnames, 'probs': probs})
        ips.append(ip)
    return ips, profiles

def select_file(profile, label):
    fnames = profile['fnames']
    probs = profile['probs'][:, label]
    idx = np.random.choice(np.arange(len(fnames)), p = probs)
    return osp.join(home_dir, fnames[idx])

def replay_pcap(fpath, iface, duration):
    Popen(['tcpreplay', '-i', iface, '--duration', str(duration), fpath], stdout=DEVNULL, stderr=DEVNULL)

@app.route('/samples')
def samples():
    data = request.data.decode('utf-8')
    jdata = json.loads(data)
    in_vals, out_vals = flow_collector.retrieve_data(jdata['window'])
    return jsonify(in_vals, out_vals)

@app.route('/reset')
def reset():
    data = request.data.decode('utf-8')
    jdata = json.loads(data)
    flow_collector.clear_queues(jdata['ip'])
    return jsonify('ok')

class FlowCollector():

    def __init__(self, qsize=100000, in_iface='obs_br', out_iface='reward_br'):
        self.in_iface = in_iface
        self.out_iface = out_iface
        self.in_queue = deque(maxlen=qsize)
        self.out_queue = deque(maxlen=qsize)
        self.qsize = qsize

    def start(self):
        in_thr = Thread(target=self._recv, args=(self.in_iface, self.in_queue), daemon=True)
        in_thr.start()
        out_thr = Thread(target=self._recv, args=(self.out_iface, self.out_queue), daemon=True)
        out_thr.start()

    def _recv(self, iface, dq):
        sniffer = pcap.pcap(name=iface, timeout_ms=10)
        while True:
            ts, raw = next(sniffer)
            try:
                id, features, flags = read_pkt(raw)
                if id is not None:
                    dq.appendleft((ts, id, features, flags))
            except Exception as e:
                print(e)
                pass

    def retrieve_data(self, window):
        tnow = datetime.now().timestamp()
        in_samples = []
        out_samples = []
        in_items = list(self.in_queue)
        out_items = list(self.out_queue)
        for item in in_items:
            if item[0] > tnow - window:
                in_samples.append(item[1:])
            else:
                break
        for item in out_items:
            if item[0] > tnow - window:
                out_samples.append(item[1:])
            else:
                break
        return in_samples, out_samples

    def clear_queues(self):
        self.in_queue.clear()
        self.out_queue.clear()

if __name__ == '__main__':

    home_dir = '/home/vagrant'
    data_dir = '{0}/data/spl'.format(home_dir)
    ips, profiles = calculate_probs(data_dir)
    seed = None

    flow_collector = FlowCollector()
    flow_collector.start()

    app.run(host='0.0.0.0')