import os, pandas, shutil
import os.path as osp
import numpy as np
import tensorflow as tf
import argparse as arp

from common.utils import vagrantfile_provider, vagrantfile_vms, vagrantfile_end, increment_ips, download_controller, clean_dir
from common.ml import load_meta
from config import *

if __name__ == '__main__':

    # parse args

    parser = arp.ArgumentParser(description='Prepare resources')
    parser.add_argument('-n', '--nenvs', help='Number of environments', type=int, default=1)
    parser.add_argument('-i', '--nidss', help='Number of IDS boxes in each environment', type=int, default=1)
    parser.add_argument('-l', '--labels', help='Model labels to compile', nargs='+', default=['1', '2', '3', '4', '1,2,3,4'])
    parser.add_argument('-e', '--exclude', help='Model labels to avoid', nargs='+', default=[])
    parser.add_argument('-s', '--storage', help='Libvirt storage pool name')
    parser.add_argument('-m', '--models', help='IDS models', nargs='+', default=['mlp'])
    args = parser.parse_args()

    # update nenvs and nidss

    if args.nenvs is not None:
        env_vms['ovs']['n'] = args.nenvs
    if args.nidss is not None:
        env_vms['ids']['n'] = args.nidss

    # preparare vagrant file

    vms, cpus, ips, sources, scripts, mounts = [], [], [], [], [], []

    for key in env_vms.keys():
        vm_ips = env_vms[key]['ips']
        for i in range(env_vms['ovs']['n']):
            for j in range(env_vms[key]['n']):
                vm_name = f'{key}_{i}_{j}'
                vms.append(vm_name)
                cpus.append(env_vms[key]['cpus'])
                ips.append(vm_ips)
                sources.append(env_vms[key]['sources'])
                mounts.append(env_vms[key]['mount'])
                scripts.append(env_vms[key]['script'])
                vm_ips = increment_ips(vm_ips)
            if env_vms[key]['unique']:
                break

    vagrant_file_lines = vagrantfile_provider(mgmt_network=mgmt_network, storage_pool_name=args.storage)
    vagrant_file_lines.extend(vagrantfile_vms(vms, cpus, ips, sources, scripts, mounts))
    vagrant_file_lines.extend(vagrantfile_end())
    with open('Vagrantfile', 'w') as f:
        f.writelines(vagrant_file_lines)

    # download controller

    download_controller(version='0.12.3')

    # input directories

    m_dir = osp.join(ids_models_dir, 'checkpoints')
    r_dir = osp.join(ids_models_dir, 'results')

    # output directories

    if not osp.isdir(ids_sources_dir):
        os.mkdir(ids_sources_dir)
    w_dir = osp.join(ids_sources_dir, 'weights')
    if not osp.isdir(w_dir):
        os.mkdir(w_dir)
    t_dir = osp.join(ids_sources_dir, 'thresholds')
    if not osp.isdir(t_dir):
        os.mkdir(t_dir)

    # clean directories

    clean_dir(w_dir, postfix='.tflite')
    clean_dir(t_dir, postfix='.thr')

    # label names

    meta = load_meta(feature_dir)
    label_names = [str(item) for item in sorted(meta['labels'])]
    non_zero_label_names = [str(item) for item in sorted(meta['labels']) if item > 0]


    # compile models and select thresholds

    model_names = [item for item in os.listdir(m_dir) if osp.isdir(osp.join(m_dir, item))]
    non_zero_label_names = []
    for model_name in model_names:
        spl = model_name.split('_')
        input_name = osp.join(m_dir, model_name)
        model_type = spl[0]
        sstep = spl[-1]
        alabel = spl[-2]
        model = '_'.join(spl[:-1])

        # check labels

        if ',' in alabel:
            alabels = alabel.split(',')
        else:
            alabels = [alabel]

        # compile?

        if model_type in args.models and alabel in args.labels:
            compile_model = True
            for al in alabels:
                if al not in label_names or al in args.exclude:
                    compile_model = False
                    break
        else:
            compile_model = False

        # compile model and copy threshold if there is any

        if compile_model:
            output_name = osp.join(w_dir, '{0}_{1}.tflite'.format(model, sstep))
            converter = tf.lite.TFLiteConverter.from_saved_model(input_name)
            tflite_model = converter.convert()
            open(output_name, "wb").write(tflite_model)

            if 'thr' in os.listdir(input_name):
                with open(osp.join(input_name, 'thr')) as f:
                    thr = f.readline().strip()
                with open(osp.join(t_dir, '{0}_{1}.thr'.format(model, sstep)), 'w') as f:
                    f.write(thr)

    # copy feature extraction functions to ids, ads and ovs vms

    for dir in [ids_sources_dir, ovs_sources_dir]:
        if not osp.isdir('{0}/common'.format(dir)):
            os.mkdir('{0}/common'.format(dir))
        shutil.copy('common/pcap.py', '{0}/common/'.format(dir))
        shutil.copy('common/data.py', '{0}/common/'.format(dir))

    # copy meta for ids and ads

    shutil.copy('{0}/metainfo.json'.format(feature_dir), ids_sources_dir)