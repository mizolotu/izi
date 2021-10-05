import tflite_runtime.interpreter as tflite
import logging, inspect

from common.data import *
from flask import Flask, request, jsonify
from threading import Thread
from collections import deque
from queue import Queue
from socket import socket, AF_PACKET, SOCK_RAW
from time import sleep

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

@app.route('/')
def info():
    return jsonify({'models': interceptor.models})

@app.route('/network')
def set_hosts_and_apps():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        interceptor.set_hosts(jdata['hosts'])
        interceptor.set_apps(jdata['applications'])
    return jsonify({'hosts': interceptor.hosts, 'applications': interceptor.apps})

@app.route('/dscp', methods=['GET', 'POST'])
def set_label():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        interceptor.set_dscp(jdata['dscp'])
    return jsonify({'dscp': interceptor.dscp})

@app.route('/reset', methods=['GET', 'POST'])
def restart():
    interceptor.reset()
    return jsonify('ok')

@app.route('/model', methods=['GET', 'POST'])
def model_label():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        interceptor.set_model(jdata['model'])
    return jsonify({'model': interceptor.models[interceptor.model_idx]})

@app.route('/threshold', methods=['GET', 'POST'])
def model_threshold():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        interceptor.set_threshold(jdata['threshold'])
    return jsonify({'threshold': interceptor.thrs[interceptor.thr_idx]})

@app.route('/intrusions')
def intrusions():
    vals = interceptor.get_intrusions()
    return jsonify(vals)

@app.route('/nflows')
def nflows():
    n = interceptor.nflows
    return jsonify({'nflows': n})

@app.route('/delay')
def delay():
    d = interceptor.delay
    return jsonify({'delay': d})

class Interceptor:

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    ECE = 0x40
    CWR = 0x80

    src_ip_idx = 0
    src_port_idx = 1
    dst_ip_idx = 2
    dst_port_idx = 3
    proto_idx = 4

    def __init__(self, iface_in, iface_out, main_path, model_idx=0, thr_idx=0, qsize=10000, nnewpkts_min=0, lasttime_min=1.0):

        self.iface_in = iface_in
        self.iface_out = iface_out
        self.pkt_q = Queue()
        self.flows = []
        self.flow_ids = []
        self.flow_labels = []
        self.intrusion_ids = deque(maxlen=qsize)
        self.model_path = osp.join(main_path, 'weights')
        self.thr_path = osp.join(main_path, 'thresholds')
        self.models = sorted(list(set([item.split('.tflite')[0] for item in os.listdir(self.model_path) if item.endswith('.tflite')])))

        with open(osp.join(main_path, 'metainfo.json'), 'r') as f:
            meta = json.load(f)
        self.xmin = np.array(meta['xmin'])
        self.xmax = np.array(meta['xmax'])

        self.sock = socket(AF_PACKET, SOCK_RAW)
        ready = False
        while not ready:
            try:
                self.sock.bind((self.iface_out, 0))
                ready = True
            except:
                sleep(1)

        self.model_idx = model_idx
        self.thr_idx = thr_idx
        self.set_model(model_idx)
        self.set_threshold(thr_idx)

        self.nnewpkts_min = nnewpkts_min
        self.lasttime_min = lasttime_min

        self.to_be_reset = False
        self.delay = 0
        self.dscp = None
        self.hosts = []
        self.apps = []

    def load_model(self, model):
        self.interpreter = tflite.Interpreter(model_path=osp.join(self.model_path, f'{model}.tflite'))
        self.model_type = model.split('_')[0]
        self.thrs = [float(item) for item in open(osp.join(self.thr_path, f'{model}.thr')).readline().strip().split(',')]

    def set_model(self, idx):
        model = self.models[idx]
        self.load_model(model)
        self.model_idx = idx

    def set_threshold(self, idx):
        self.thr_idx = idx

    def set_dscp(self, dscp):
        self.dscp = dscp

    def reset(self):
        model_idx = 0
        self.set_model(model_idx)
        self.to_be_reset = True

    def append_packets(self):
        while True:
            try:

                # get next timestamp and packet

                if not self.pkt_q.empty():
                    timestamp, raw = self.pkt_q.get()
                    id, features, flags, ether, tos = read_pkt(raw)
                    if id is not None:

                        # add packets to flows

                        reverse_id = [id[self.dst_ip_idx], id[self.dst_port_idx], id[self.src_ip_idx], id[self.src_port_idx], id[self.proto_idx]]
                        if id in self.flow_ids:
                            direction = 1
                            idx = self.flow_ids.index(id)
                            self.flows[idx].append(timestamp, features, flags, direction)
                            flow_label = self.flow_labels[idx]
                        elif reverse_id in self.flow_ids:
                            direction = -1
                            idx = self.flow_ids.index(reverse_id)
                            self.flows[idx].append(timestamp, features, flags, direction)
                            flow_label = self.flow_labels[idx]
                        else:
                            self.flow_ids.append(id)
                            self.flows.append(Flow(timestamp, id, features, flags))
                            flow_label = 0
                            self.flow_labels.append(flow_label)

                        if self.dscp is not None:
                            dscp = flow_label << (2 + self.dscp)
                            ether[ip.IP].tos = tos | dscp
                            raw = ether.bin()

                        try:
                            self.sock.send(raw)
                        except Exception as e:
                            print(e)
                            print(id, tos)
            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                print(e, fname, exc_tb.tb_lineno)

    def classify(self):

        while True:

            # remove old flows

            tmp_ids = []
            tmp_objects = []
            for i, o in zip(self.flow_ids, self.flows):
                if o.is_active:
                    tmp_ids.append(i)
                    tmp_objects.append(o)
            self.flow_ids = list(tmp_ids)
            self.flows = list(tmp_objects)

            # label flows

            tnow = datetime.now().timestamp()
            for i, (flow_id, flow_object) in enumerate(zip(self.flow_ids, self.flows)):
                if self.flow_labels[i] == 0 and (flow_object.nnewpkts > self.nnewpkts_min or (tnow - flow_object.lasttime) > self.lasttime_min):
                    try:
                        p = self.analyze_flow(i)
                    except:
                        p = -np.inf
                    if p > self.thrs[self.thr_idx]:
                        self.intrusion_ids.appendleft(self.flow_ids[i])
                        self.flow_labels[i] = 1
                        #print(flow_id)
            self.delay = datetime.now().timestamp() - tnow
            self.nflows = len(self.flow_ids)

    def start(self):

        try:
            reader = pcap.pcap(name=self.iface_in)
            while True:
                timestamp, raw = next(reader)
                self.pkt_q.put((timestamp, raw))

                # reset if needed

                if self.to_be_reset:
                    print('Reseting...')
                    with self.pkt_q.mutex:
                        self.pkt_q.queue.clear()
                    self.flow_ids = []
                    self.flows = []
                    self.intrusion_ids.clear()
                    self.to_be_reset = False

        except Exception as e:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            print(e, fname, exc_tb.tb_lineno)

    def predict(self, x):
        self.interpreter.allocate_tensors()
        input_details = self.interpreter.get_input_details()
        output_details = self.interpreter.get_output_details()
        self.interpreter.set_tensor(input_details[0]['index'], x)
        self.interpreter.invoke()
        p = self.interpreter.get_tensor(output_details[0]['index'])[0]
        return p

    def calculate_flow_features(self, flow_idx):
        flow = self.flows[flow_idx]
        flow_features = flow.get_features()
        return flow_features

    def analyze_flow(self, flow_idx):
        flow_features = self.calculate_flow_features(flow_idx)
        flow_features = (flow_features - self.xmin) / (self.xmax - self.xmin + 1e-10)
        prediction = self.predict(np.array(flow_features, dtype=np.float32).reshape(1, -1, len(self.xmin)))
        if self.model_type == 'aen':
            result = np.mean(np.linalg.norm(prediction - flow_features, axis=-1), axis=-1)
        elif self.model_type in ['som', 'bgn']:
            result = prediction
        else:
            result = prediction[0]
        return result

    def get_intrusions(self):
        intrusions = list(self.intrusion_ids)
        self.intrusion_ids.clear()
        return intrusions

if __name__ == "__main__":

    fname = inspect.getframeinfo(inspect.currentframe()).filename
    model_path = os.path.dirname(os.path.abspath(fname))
    iface_in = 'in_br'
    iface_out = 'out_br'

    interceptor = Interceptor(iface_in, iface_out, model_path)

    intercept_thread = Thread(target=interceptor.start, daemon=True)
    intercept_thread.start()

    ap_thread = Thread(target=interceptor.append_packets, daemon=True)
    ap_thread.start()

    cl_thread = Thread(target=interceptor.classify, daemon=True)
    cl_thread.start()

    app.run(host='0.0.0.0')

