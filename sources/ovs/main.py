import json, logging, pcap
import numpy as np
import os.path as osp

from subprocess import Popen, DEVNULL, PIPE
from collections import deque
from threading import Thread
from flask import Flask, request, jsonify
from datetime import datetime
from common.data_old import read_pkt_faster

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

@app.route('/readpcap', methods=['POST'])
def readpcap():
    data = request.data.decode('utf-8')
    jdata = json.loads(data)
    fname = jdata['fname']
    augment = jdata['augment']
    added = tg.readpcap(fname, augment)
    return jsonify(added)

@app.route('/replay', methods=['POST'])
def replay():
    data = request.data.decode('utf-8')
    jdata = json.loads(data)
    duration = jdata['duration']
    tg.replay(duration)
    return jsonify('ok')

@app.route('/samples')
def samples():
    data = request.data.decode('utf-8')
    jdata = json.loads(data)
    vals = flow_collector.retrieve_data(jdata['window'])
    return jsonify(vals)

@app.route('/app_counts')
def app_counts():
    data = request.data.decode('utf-8')
    jdata = json.loads(data)
    apps, pkts, bts = flow_collector.parse_app_table(jdata['table'])
    return jsonify({'applications': apps, 'packets': pkts, 'bytes': bts})

@app.route('/ip_counts')
def ip_counts():
    data = request.data.decode('utf-8')
    jdata = json.loads(data)
    ips_pass, pkts_pass, bts_pass, ips_drop, pkts_drop, bts_drop = flow_collector.parse_ip_table(jdata['table'])
    return jsonify({'ips_pass': ips_pass, 'packets_pass': pkts_pass, 'bytes_pass': bts_pass, 'ips_drop': ips_drop, 'packets_drop': pkts_drop, 'bytes_drop': bts_drop})

@app.route('/report')
def report():
    in_pkts = [[ts, *read_pkt_faster(pkt)] for ts, pkt in list(flow_collector.in_pkts)]
    out_pkts = [[ts, *read_pkt_faster(pkt)] for ts, pkt in list(flow_collector.out_pkts)]
    return jsonify({'in_pkts': in_pkts, 'out_pkts': out_pkts, 'timestamps': list(flow_collector.state_timestamps)})

@app.route('/reset')
def reset():
    flow_collector.clear_queues()
    return jsonify('ok')

class TrafficGenerator():

    def __init__(self, iface, homedir):
        self.iface = iface
        self.homedir = homedir
        self.pkts = {0: [], 1: []}
        #self.sock =

    def readpcap(self, fname, augment):
        fpath = osp.join(self.homedir, fname)
        pkts = []
        ts_last = None
        raw_last = None
        try:
            reader = pcap.pcap(name=fpath)
            while True:
                try:
                    ts, raw = next(reader)
                    if ts_last is not None and raw_last is not None:
                        pkts.append([ts - ts_last, raw_last])
                    ts_last = ts
                    raw_last = raw
                except:
                    pkts.append([None, raw_last])
                    break
            self.pkts[augment].append(pkts)
            added = True
        except:
            added = False
        return added

    def replay(self, duration):

        # replay packets in separate threads

        thrs = []
        for key in self.pkts.keys():
            for pkt_list in self.pkts[key]:
                thrs.append(Thread(target=self._sendpkts, args=(pkt_list, duration, key), daemon=True))
        for thr in thrs:
            thr.start()

        # clear pkts

        self.pkts = {0: [], 1: []}

    def _sendpkts(self, pkt_list, duration, augment):
        for ts, pkt in pkt_list:
            if ts is None:
                print(ts)

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
        samples = [read_pkt_faster(item[1]) for item in in_items if item[0] > tnow - window]
        return samples

    def clear_queues(self):
        self.in_pkts.clear()
        self.out_pkts.clear()
        self.state_timestamps.clear()

    def parse_app_table(self, table):
        cmd = ['sudo', 'ovs-ofctl', 'dump-flows', 'br', f'table={table}']
        with Popen(cmd, stdout=PIPE) as p:
            lines = p.stdout.readlines()
        lines = [line.decode()[1:].strip() for line in lines]
        apps = []
        pkts = []
        bts = []
        for line in lines:
            spl = line.split(', ')
            if len(spl) >= 7:
                npkts = int(spl[3].split('n_packets=')[1])
                nbts = int(spl[4].split('n_bytes=')[1])
                match_actions_spl = spl[6].split(' actions=')
                match_spl = match_actions_spl[0].split(',')
                if len(match_spl) == 2:
                    proto = match_spl[1]
                    app = (proto,)
                    apps.append(app)
                    pkts.append(npkts)
                    bts.append(nbts)
                elif len(match_spl) == 3:
                    proto = match_spl[1]
                    port = int(match_spl[2].split('=')[1])
                    app = (proto, port)
                    if app in apps:
                        idx = apps.index(app)
                        pkts[idx] += npkts
                        bts[idx] += nbts
                    else:
                        apps.append(app)
                        pkts.append(npkts)
                        bts.append(nbts)
        return apps, pkts, bts

    def parse_ip_table(self, table):
        cmd = ['sudo', 'ovs-ofctl', 'dump-flows', 'br', f'table={table}']
        with Popen(cmd, stdout=PIPE) as p:
            lines = p.stdout.readlines()
        lines = [line.decode()[1:].strip() for line in lines]
        ips_pass = []
        pkts_pass = []
        bts_pass = []
        ips_drop = []
        pkts_drop = []
        bts_drop = []
        for line in lines:
            spl = line.split(', ')
            if len(spl) >= 7:
                npkts = int(spl[3].split('n_packets=')[1])
                nbts = int(spl[4].split('n_bytes=')[1])
                match_actions_spl = spl[6].split(' actions=')
                match_spl = match_actions_spl[0].split(',')
                action = match_actions_spl[1]
                if len(match_spl) == 2:
                    ips_pass.append('')
                    pkts_pass.append(npkts)
                    bts_pass.append(nbts)
                elif len(match_spl) >= 3 and action == 'drop':
                    ip = match_spl[2].split('=')[1]
                    if ip in ips_drop:
                        idx = ips_drop.index(ip)
                        pkts_drop[idx] += npkts
                        bts_drop[idx] += nbts
                    else:
                        ips_drop.append(ip)
                        pkts_drop.append(npkts)
                        bts_drop.append(nbts)
                elif len(match_spl) == 3:
                    ip = match_spl[2].split('=')[1]
                    if ip in ips_pass:
                        idx = ips_pass.index(ip)
                        pkts_pass[idx] += npkts
                        bts_pass[idx] += nbts
                    else:
                        ips_pass.append(ip)
                        pkts_pass.append(npkts)
                        bts_pass.append(nbts)
        return ips_pass, pkts_pass, bts_pass, ips_drop, pkts_drop, bts_drop

if __name__ == '__main__':

    iface = 'in_br'
    home_dir = '/home/vagrant'
    tg = TrafficGenerator(iface, home_dir)

    flow_collector = FlowCollector()
    #flow_collector.start()

    app.run(host='0.0.0.0')