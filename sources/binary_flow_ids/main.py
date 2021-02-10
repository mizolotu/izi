import numpy as np
import tflite_runtime.interpreter as tflite
import os.path as osp
import os, json, logging

from netfilterqueue import NetfilterQueue
from scapy.all import *
from utils import *
from flask import Flask, request, jsonify
from threading import Thread

app = Flask(__name__)
#log = logging.getLogger('werkzeug')
#log.setLevel(logging.ERROR)

@app.route('/dscp', methods=['GET', 'POST'])
def dscp_label():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        interceptor.set_dscp(jdata['dscp'])
    return jsonify({'dscp': interceptor.dscp_label})

@app.route('/model', methods=['GET', 'POST'])
def model_label():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        interceptor.set_model(jdata['model'])
    return jsonify({'model': interceptor.model_labels[interceptor.model_idx]})

@app.route('/threshold', methods=['GET', 'POST'])
def threshold_label():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        interceptor.set_thr(jdata['threshold'])
    return jsonify({'threshold': interceptor.thrs[interceptor.thr_idx]})

# packet features like in extract features

#timestamp
#src_ip
#src_port
#dst_ip
#dst_port
#proto
#frame_size
#header_size
#payload_size
#window
# flags as vector [FIN, SYN, RST, PSH, ACK, URG, ECE, CWR]

class Interceptor:

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    src_ip_idx = 1
    src_port_idx = 2
    dst_ip_idx = 3
    dst_port_idx = 4
    proto_idx = 5

    def __init__(self, dscp_label, model_path, model_idx=0, thr_idx=0):

        self.flows = []
        self.flow_ids = []
        self.intrusion_ids = []
        self.dscp_label = dscp_label

        self.model_path = model_path
        self.model_labels = sorted([item.split('.tflite')[0] for item in os.listdir(model_path) if item.endswith('.tflite')])
        print(self.model_labels)
        with open(osp.join(model_path, 'metainfo.json'), 'r') as f:
            meta = json.load(f)
        self.xmin = np.array(meta['xmin'])
        self.xmax = np.array(meta['xmax'])
        self.set_model(model_idx)
        self.set_thr(thr_idx)

    def set_dscp(self, label):
        self.dscp_label = label

    def set_model(self, idx):
        model_label = self.model_labels[idx]
        self.interpreter = tflite.Interpreter(model_path=osp.join(self.model_path, '{0}.tflite'.format(model_label)))
        with open(osp.join(model_path, '{0}.thr'.format(model_label)), 'r') as f:
            line = f.readline().strip()
        self.thrs = [float(item) for item in line.split(',')]
        self.model_idx = idx

    def set_thr(self, idx):
        self.thr_idx = idx

    def add2flow(self, pkt, flags):
        """Creates or appends to flow as needed. Returns flow idx if flow in need of classification"""
        just_id = pkt[1:6]
        reverse_id = [pkt[self.dst_ip_idx], pkt[self.dst_port_idx], pkt[self.src_ip_idx], pkt[self.src_port_idx], pkt[self.proto_idx]]
        if flags[1] and not flags[4]:    # SYN without ACK
            if just_id in self.flow_ids:
                idx = self.flow_ids.index(just_id)
                self.flows[idx].append(pkt,flags,1)
                return idx
            elif reverse_id in self.flow_ids:
                idx = self.flow_ids.index(reverse_id)
                self.flows[idx].append(pkt,flags,-1)
                return idx
            else:
                self.flow_ids.append(just_id)
                self.flows.append(Flow(pkt,flags))
                return -1
        elif flags[0] and not flags[3] or flags[2]:  # FIN without PSH or RST
            if just_id in self.flow_ids:
                idx = self.flow_ids.index(just_id)
                del self.flow_ids[idx]
                del self.flows[idx]
            elif reverse_id in self.flow_ids:
                idx = self.flow_ids.index(reverse_id)
                del self.flow_ids[idx]
                del self.flows[idx]
            return -1
        else:
            if just_id in self.flow_ids:
                idx = self.flow_ids.index(just_id)
                self.flows[idx].append(pkt,flags,1)
                return idx
            elif reverse_id in self.flow_ids:
                idx = self.flow_ids.index(reverse_id)
                self.flows[idx].append(pkt,flags,-1)
                return idx
            elif pkt[self.proto_idx] == 17:  # UDP
                self.flow_ids.append(just_id)
                self.flows.append(Flow(pkt,flags))
            else:
                return -1

    def extract_pkt_features(self, pkt):
        features = [
            pkt.time,
            pkt.src,
            pkt.sport,
            pkt.dst,
            pkt.dport,
            pkt.proto,
            len(pkt),                       # frame_size
            len(pkt) - len(pkt.payload),    # ip header_size
            len(pkt.payload),               # payload_size
            pkt.window if pkt.proto == 6 else 0
            ]
        if pkt.proto == 6:
            flags = [
                pkt[TCP].flags.F,    # FIN
                pkt[TCP].flags.S,    # SYN
                pkt[TCP].flags.R,    # RST
                pkt[TCP].flags.P,    # PSH
                pkt[TCP].flags.A,    # ACK
                pkt[TCP].flags.U,    # URG
                pkt[TCP].flags.E,    # ECE
                pkt[TCP].flags.C     # CWR
                ]
        else:
            flags = [0]*8
        return features, flags

    def intercept(self, packet):
        try:
            is_intrusion = False
            pkt = IP(packet.get_payload())
            if pkt.haslayer(TCP) or pkt.haslayer(UDP):
                pkt_features, pkt_flags = self.extract_pkt_features(pkt)
                just_id = pkt_features[1:6]
                reverse_id = [pkt_features[self.dst_ip_idx], pkt_features[self.dst_port_idx], pkt_features[self.src_ip_idx], pkt_features[self.src_port_idx], pkt_features[self.proto_idx]]
                flow_idx = self.add2flow(pkt_features, pkt_flags)
                if flow_idx >= 0:
                    if just_id in self.intrusion_ids or reverse_id in self.intrusion_ids:
                        is_intrusion = True
                    prob = self.analyze_flow(flow_idx)
                    if prob > self.thrs[self.thr_idx]:
                        is_intrusion = True
                        if just_id not in self.intrusion_ids:
                            self.intrusion_ids.append(just_id)
                        if reverse_id not in self.intrusion_ids:
                            self.intrusion_ids.append(reverse_id)
                    if is_intrusion:
                        bitlabel = 1 << (2 + self.dscp_label)
                        pkt[IP].tos = pkt[IP].tos | bitlabel
                        del pkt[IP].chksum
                        if pkt.haslayer(TCP):
                            del pkt[TCP].chksum
                        if pkt.haslayer(UDP):
                            del pkt[UDP].chksum
                        packet.set_payload(bytes(pkt))
        except Exception as e:
            print(e)
        finally:
            packet.accept()

    def predict(self, x):
        self.interpreter.allocate_tensors()
        input_details = self.interpreter.get_input_details()
        output_details = self.interpreter.get_output_details()
        self.interpreter.set_tensor(input_details[0]['index'], x)
        self.interpreter.invoke()
        p = self.interpreter.get_tensor(output_details[0]['index'])[0][0]
        return p

    def calculate_flow_features(self, flow_idx):
        flow = self.flows[flow_idx]
        flow_features = flow.get_features()
        return flow_features

    def analyze_flow(self, flow_idx):
        flow_features = self.calculate_flow_features(flow_idx)
        flow_features = (flow_features - self.xmin) / (self.xmax - self.xmin + 1e-10)
        return self.predict(np.array(flow_features, dtype=np.float32).reshape(1,len(flow_features)))

if __name__ == "__main__":

    dscp_label = 0
    model_path = '/home/vagrant/binary_flow_ids/models'

    interceptor = Interceptor(dscp_label, model_path)
    nfqueue = NetfilterQueue()
    nfqueue.bind(0, interceptor.intercept)
    nfq_thread = Thread(target=nfqueue.run, daemon=True)
    nfq_thread.start()
    app.run(host='0.0.0.0')
    nfqueue.unbind()

