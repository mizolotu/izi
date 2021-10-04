import json, logging, pcap, os
import numpy as np
import os.path as osp

from subprocess import Popen, PIPE
from collections import deque
from threading import Thread
from flask import Flask, request, jsonify
from datetime import datetime
from common.data import read_pkt
from socket import socket, AF_PACKET, SOCK_RAW
from time import sleep, time

from pypacker.layer12 import ethernet
from pypacker.layer3 import ip
from pypacker.layer4 import tcp

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

@app.route('/flag_counts')
def flag_counts():
    data = request.data.decode('utf-8')
    jdata = json.loads(data)
    flags, pkts, bts = flow_collector.parse_flag_table(jdata['table'])
    return jsonify({'flags': flags, 'packets': pkts, 'bytes': bts})

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
    in_pkts = [[ts, *read_pkt(pkt, read_proto=False)] for ts, pkt in list(flow_collector.in_pkts)]
    out_pkts = [[ts, *read_pkt(pkt, read_proto=False)] for ts, pkt in list(flow_collector.out_pkts)]
    return jsonify({'in_pkts': in_pkts, 'out_pkts': out_pkts, 'timestamps': list(flow_collector.state_timestamps)})

@app.route('/reset')
def reset():
    flow_collector.clear_queues()
    return jsonify('ok')

class TrafficGenerator():

    def __init__(self, iface, homedir):
        self.iface = iface
        self.homedir = homedir
        self.pkts = []
        self.sock = socket(AF_PACKET, SOCK_RAW)
        self.sock.bind((self.iface, 0))
        self.iat = 0.01
        self.pad = 100
        self.zpd = 0.005
        self.zpp = 60

    def readpcap(self, fname, augment):
        fpath = osp.join(self.homedir, fname)
        pkts = []
        ts_last = None
        raw_last = None
        aug_last = None
        id_last = None
        traffic_duration = 0
        try:
            reader = pcap.pcap(name=fpath)
            while True:
                try:
                    ts, raw = next(reader)
                    if ts_last is not None:
                        tdelta = ts - ts_last
                        pkts.append([tdelta, raw_last, id_last, aug_last])
                        traffic_duration += tdelta
                    aug = False
                    if augment is not None:
                        id, features, flags, tos = read_pkt(raw)
                        if ('source' in augment['directions'] and id[0] in augment['ips'] or 'destination' in augment['directions'] and id[2] in augment['ips']) and flags[3]:
                            aug = True
                    else:
                        id = []
                    ts_last = ts
                    raw_last = raw
                    aug_last = aug
                    id_last = id.copy()
                except Exception as e:
                    print(e)
                    pkts.append([0, raw_last, id_last, aug_last])
                    break
            self.pkts.append([traffic_duration, pkts])
            added = True
        except:
            added = False
        return added

    def replay(self, duration):
        thrs = []
        for traffic_duration, pkt_list in self.pkts:
            delay = np.random.rand() * (duration - traffic_duration)
            thrs.append(Thread(target=self._sendpkts, args=(pkt_list, delay, duration), daemon=True))
        for thr in thrs:
            thr.start()
        self.tstart = time()
        self.pkts = []

    def _sendpkts(self, pkt_list, delay, duration):
        td_total = 0
        sleep(delay)
        for td, pkt, id, aug in pkt_list:
            if aug:
                pkts_to_send = self._augment_pkt(pkt, id, td)
            else:
                pkts_to_send = [(td, pkt)]
            for td, pkt in pkts_to_send:
                try:
                    self.sock.send(pkt)
                except Exception as e:
                    print(e, len(pkt))
                sleep(td)
                td_total += td
            if td_total > duration:
                break

    def _augment_pkt(self, pkt, id):
        if self.iat > self.zpd:
            pa = self._generate_zero_pkt(*id)
            a = self._generate_ack(*id)
            td = np.random.rand() * (self.iat - self.zpd)
            pkts = [
                (self.zpd, pa),
                (td, a)
            ]
        else:
            pkts = []
        pkt += bytearray(os.urandom(self.pad))
        pkts.append((self.iat, pkt))
        return pkts

    def _generate_ack(self, src_ip, src_port, dst_ip, dst_port, proto):
        assert proto == 6
        ack = ethernet.Ethernet() + ip.IP(src_s=dst_ip, dst_s=src_ip) + tcp.TCP(sport=dst_port, dport=src_port, flags=16)
        return ack.bin()

    def _generate_zero_pkt(self, src_ip, src_port, dst_ip, dst_port, proto):
        assert proto == 6
        zp = ethernet.Ethernet() + ip.IP(src_s=src_ip, dst_s=dst_ip) + tcp.TCP(sport=src_port, dport=dst_port, flags=24, body_bytes=bytearray(self.zpp))
        return zp.bin()

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
        samples = [read_pkt(item[1], read_ip_proto=False) for item in in_items if item[0] > tnow - window]
        return samples

    def clear_queues(self):
        self.in_pkts.clear()
        self.out_pkts.clear()
        self.state_timestamps.clear()

    def parse_flag_table(self, table):
        cmd = ['sudo', 'ovs-ofctl', 'dump-flows', 'br', f'table={table}']
        with Popen(cmd, stdout=PIPE) as p:
            lines = p.stdout.readlines()
        lines = [line.decode()[1:].strip() for line in lines]
        flags = []
        pkts = []
        bts = []
        for line in lines:
            spl = line.split(', ')
            if len(spl) >= 7:
                npkts = int(spl[3].split('n_packets=')[1])
                nbts = int(spl[4].split('n_bytes=')[1])
                match_actions_spl = spl[6].split(' actions=')
                match_spl = match_actions_spl[0].split(',')
                if len(match_spl) == 3:
                    f = match_spl[2].split('=')[1]
                    flags.append(f)
                    pkts.append(npkts)
                    bts.append(nbts)
        return flags, pkts, bts

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