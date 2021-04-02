import tflite_runtime.interpreter as tflite
import logging, pcap

from sources.fcu.common.data import *
from flask import Flask, request, jsonify
from threading import Thread

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

@app.route('/reset')
def restart():
    interceptor.reset()
    return jsonify('ok')

@app.route('/step', methods=['GET', 'POST'])
def polling_step():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        interceptor.set_step(jdata['step'])
    return jsonify({'step': interceptor.model_steps[interceptor.step_idx]})

@app.route('/model', methods=['GET', 'POST'])
def model_label():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        interceptor.set_model(jdata['model'])
    return jsonify({'model': interceptor.model_labels[interceptor.model_idx]})

@app.route('/intrusions')
def intrusions():
    vals = interceptor.intrusion_ids
    return jsonify(vals)

@app.route('/nflows')
def nflows():
    n = interceptor.nflows
    return jsonify({'nflows': n})

@app.route('/delay')
def delay():
    d = interceptor.delay
    return jsonify({'delay': d})

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

    src_ip_idx = 0
    src_port_idx = 1
    dst_ip_idx = 2
    dst_port_idx = 3
    proto_idx = 4

    def __init__(self, iface, main_path, model_idx=0, step_idx=0):

        self.iface = iface
        self.flows = []
        self.flow_ids = []
        self.intrusion_ids = []

        self.model_path = osp.join(main_path, 'weights')
        self.model_labels = sorted(list(set([item.split('.tflite')[0].split('_')[1] for item in os.listdir(self.model_path) if item.endswith('.tflite')])))
        self.model_steps = sorted(list(set([item.split('.tflite')[0].split('_')[0] for item in os.listdir(self.model_path) if item.endswith('.tflite')])))
        with open(osp.join(main_path, 'metainfo.json'), 'r') as f:
            meta = json.load(f)
        self.xmin = np.array(meta['xmin'])
        self.xmax = np.array(meta['xmax'])
        self.model_idx = model_idx
        self.step_idx = step_idx
        self.set_model(model_idx)
        self.set_step(step_idx)
        self.to_be_reset = False

    def set_model(self, idx):
        model_label = self.model_labels[idx]
        model_step = self.model_steps[self.step_idx]
        self.interpreter = tflite.Interpreter(model_path=osp.join(self.model_path, '{0}_{1}.tflite'.format(model_step, model_label)))
        self.model_idx = idx

    def set_step(self, idx):
        model_step = self.model_steps[idx]
        model_label = self.model_labels[self.model_idx]
        self.interpreter = tflite.Interpreter(model_path=osp.join(self.model_path, '{0}_{1}.tflite'.format(model_step, model_label)))
        self.step_idx = idx

    def reset(self):
        step_idx = 0
        model_idx = 0
        self.set_model(model_idx)
        self.set_step(step_idx)
        self.to_be_reset = True

    def start(self):
        tstart = datetime.now().timestamp()
        step = float(self.model_steps[self.step_idx])
        try:
            reader = pcap.pcap(name=self.iface)
            while True:
                timestamp, raw = next(reader)
                id, features, flags = read_pkt(raw)
                if id is not None:

                    # add packets to flows

                    reverse_id = [id[self.dst_ip_idx], id[self.dst_port_idx], id[self.src_ip_idx], id[self.src_port_idx], id[self.proto_idx]]
                    if id in self.flow_ids:
                        direction = 1
                        idx = self.flow_ids.index(id)
                        self.flows[idx].append(timestamp, features, flags, direction)
                    elif reverse_id in self.flow_ids:
                        direction = -1
                        idx = self.flow_ids.index(reverse_id)
                        self.flows[idx].append(timestamp, features, flags, direction)
                    else:
                        self.flow_ids.append(id)
                        self.flows.append(Flow(timestamp, id, features, flags))

                if timestamp > (tstart + step):

                    # remove old flows

                    tmp_ids = []
                    tmp_objects = []
                    for i, o in zip(self.flow_ids, self.flows):
                        if o.is_active:
                            tmp_ids.append(i)
                            tmp_objects.append(o)
                            self.flow_ids = list(tmp_ids)
                            self.flows = list(tmp_objects)

                    # calculate_features

                    tnow = datetime.now().timestamp()
                    for i in range(len(self.flows)):
                        try:
                            p = self.analyze_flow(i)
                        except:
                            p = 0
                        if p > 0.5:
                            self.intrusion_ids.append(self.flow_ids[i])
                    self.delay = datetime.now().timestamp() - tnow
                    self.nflows = len(self.flow_ids)

                    # update time

                    tstart = datetime.now().timestamp()
                    step = float(self.model_steps[self.step_idx])

                    # reset if needed

                    if self.to_be_reset:
                        print('Reseting...')
                        self.flow_ids = []
                        self.flows = []
                        self.intrusion_ids = []
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

    model_path = '/home/vagrant/ids/'
    iface = 'vxlan_sys_4789'

    interceptor = Interceptor(iface, model_path)
    intercept_thread = Thread(target=interceptor.start, daemon=True)
    intercept_thread.start()
    app.run(host='0.0.0.0')

