import os, json, logging, pandas
import os.path as osp
import numpy as np

from subprocess import Popen, DEVNULL
from pathlib import Path
from flask import Flask, request, jsonify

app = Flask(__name__)
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

@app.route('/replay', methods=['GET', 'POST'])
def replay():
    if request.method == 'POST':
        data = request.data.decode('utf-8')
        jdata = json.loads(data)
        duration = jdata['duration']
        label = jdata['label']
        idx = jdata['idx']
        ip = jdata['ip']
        iface = 'in{0}'.format(idx)
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

if __name__ == "__main__":
    home_dir = '/home/vagrant'
    data_dir = '{0}/data/spl'.format(home_dir)
    ips, profiles = calculate_probs(data_dir)
    app.run(host='0.0.0.0')

