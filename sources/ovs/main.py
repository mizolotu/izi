import json, logging, pcap, pandas, os, shutil
import numpy as np
import os.path as osp

from subprocess import Popen, DEVNULL
from pathlib import Path
from collections import deque
from threading import Thread
from flask import Flask, request, jsonify
from datetime import datetime
from common.data import read_pkt
from scapy.all import *

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

@app.route('/prepare', methods=['GET', 'POST'])
def prepare():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        label = jdata['label']
        ips = jdata['ips']
        for ip in ips:
            ipidx = ips.index(ip)
            profile = profiles[ipidx]
            fpath = select_file(profile, label)
            shutil.copy(fpath, episode_raw_dir)
        modify_pcaps()
    return jsonify('ok')

@app.route('/replay', methods=['GET', 'POST'])
def replay():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        duration = jdata['duration']
        for pcap_file in os.listdir(episode_mod_dir):
            pcap_fpath = osp.join(episode_mod_dir, pcap_file)
            replay_pcap(pcap_fpath, iface, duration)
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

    return ips, profiles

def select_file(profile, label):
    fnames = profile['fnames']
    probs = profile['probs'][:, label]
    idx = np.random.choice(np.arange(len(fnames)), p = probs)
    return osp.join(home_dir, fnames[idx])

def add_load_to_pkt(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(Raw) or pkt.haslayer(UDP) and pkt.haslayer(Raw):
        load = pkt.load
        l = len(load)
        n = np.random.randint(l)
        pad = Padding()
        pad.load = '\x00' * n
        pkt = pkt / pad
        del pkt[IP].len
        del pkt[IP].chksum
        if pkt.haslayer(TCP):
            del pkt[TCP].chksum
        elif pkt.haslayer(UDP):
            del pkt[UDP].chksum
            del pkt[UDP].len
        t = pkt.time
        pkt = Ether(pkt.build())
        pkt.time = t
    return pkt

def add_time_to_pkt(last_two_pkts, new_pkt):
    if new_pkt.haslayer(TCP) or new_pkt.haslayer(UDP) :
        second_last_pkt = last_two_pkts[0]
        last_pkt = last_two_pkts[1]
        if new_pkt.time > second_last_pkt.time:
            iat = new_pkt.time - second_last_pkt.time
            dt = np.random.rand() * iat
            last_pkt.time = second_last_pkt.time + dt
    return second_last_pkt, last_pkt

def modify_pcaps():

    # clear mod dir

    for old_file in os.listdir(episode_mod_dir):
        os.unlink(osp.join(episode_mod_dir, old_file))

    # modify files

    pcap_files = os.listdir(episode_raw_dir)
    for pcap_file in pcap_files:
        pcap_fpath = osp.join(episode_raw_dir, pcap_file)
        if osp.isfile(pcap_fpath):

            # output file

            output_fpath = osp.join(episode_mod_dir, pcap_file)

            # read packets, track flows

            pkts = rdpcap(pcap_fpath)
            flows = []
            flow_last_two_packets = []
            mods = []
            for pkt in pkts:
                if pkt.haslayer('IP'):
                    ip = pkt[IP]
                    src_ip = ip.src
                    dst_ip = ip.dst
                    src_port = ip.sport
                    dst_port = ip.dport
                    proto = ip.proto

                    # check flows

                    if [src_ip, src_port, dst_ip, dst_port, proto] in flows:
                        idx = flows.index([src_ip, src_port, dst_ip, dst_port, proto])
                    elif [dst_ip, dst_port, src_ip, src_port, proto] in flows:
                        idx = flows.index([dst_ip, dst_port, src_ip, src_port, proto])
                    else:
                        flows.append([src_ip, src_port, dst_ip, dst_port, proto])
                        flow_last_two_packets.append(deque(maxlen=2))
                        idx = -1

                    # add load

                    pkt = add_load_to_pkt(pkt)

                    # add to deque

                    if len(flow_last_two_packets[idx]) == 2:
                        pkt0, pkt1 = add_time_to_pkt(flow_last_two_packets[idx], pkt)
                        flow_last_two_packets[idx].append(pkt0)
                        flow_last_two_packets[idx].append(pkt1)
                        mods.append(flow_last_two_packets[idx][0])
                    flow_last_two_packets[idx].append(pkt)

            # add the rest of the packets

            for item_list in flow_last_two_packets:
                for item in item_list:
                    mods.append(item)

            # save in the output fpath

            wrpcap(output_fpath, mods)

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

    def __init__(self, qsize=100000, in_iface='obs_br', out_iface='rew_br'):
        self.in_iface = in_iface
        self.out_iface = out_iface
        self.in_samples = []
        self.out_samples = []
        self.in_queue = deque(maxlen=qsize)
        self.out_queue = deque(maxlen=qsize)
        self.qsize = qsize

    def start(self):
        in_thr = Thread(target=self._recv, args=(self.in_iface, self.in_queue), daemon=True)
        in_thr.start()
        out_thr = Thread(target=self._recv, args=(self.out_iface, self.out_queue), daemon=True)
        out_thr.start()

    def _recv(self, iface, dq):
        ready = False
        while not ready:
            try:
                sniffer = pcap.pcap(name=iface, timeout_ms=10)
                ready = True
                while True:
                    ts, raw = next(sniffer)
                    try:
                        id, features, flags = read_pkt(raw)
                        if id is not None:
                            dq.appendleft((ts, id, features, flags))
                    except Exception as e:
                        print(e)
            except Exception as e:
                print(e)


    def retrieve_data(self, window):
        in_thr = Thread(target=self._retrieve_data_in, args=(window,), daemon=True)
        in_thr.start()
        out_thr = Thread(target=self._retrieve_data_out, args=(window,), daemon=True)
        out_thr.start()
        for thr in [in_thr, out_thr]:
            thr.join()
        return self.in_samples, self.out_samples

    def _retrieve_data_in(self, window):
        tnow = datetime.now().timestamp()
        self.in_samples = []
        in_items = list(self.in_queue)
        for item in in_items:
            if item[0] > tnow - window:
                self.in_samples.append(item[1:])
            else:
                break

    def _retrieve_data_out(self, window):
        tnow = datetime.now().timestamp()
        self.out_samples = []
        out_items = list(self.out_queue)
        for item in out_items:
            if item[0] > tnow - window:
                self.out_samples.append(item[1:])
            else:
                break

    def clear_queues(self):
        self.in_queue.clear()
        self.out_queue.clear()

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