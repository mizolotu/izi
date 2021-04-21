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
    parser.add_argument('-n', '--nenvs', help='Number of environments')
    parser.add_argument('-i', '--nidss', help='Number of IDS boxes in each environment')
    parser.add_argument('-s', '--storage', help='Libvirt storage pool name')
    args = parser.parse_args()

    # update nenvs and nidss

    if args.nenvs is not None:
        nenvs = args.nenvs
    if args.nidss is not None:
        nidss = args.nidss

    # preparare vagrant file

    vms, ips, sources, scripts, mounts = [], [], [], [], []

    # add controller

    vms.append('odl')
    ips.append(ctrl_ips)
    sources.append(ctrl_sources)
    scripts.append(ctrl_script)
    mounts.append(None)

    # add ovs vms

    ips_i = ovs_ips
    for i in range(nenvs):
        vms.append(f'ovs_{i}')
        ips.append(ips_i)
        sources.append(ovs_sources)
        scripts.append(ovs_script)
        mounts.append(ovs_mount)
        ips_i = increment_ips(ips_i)

    # add ids vms

    ips_i = ids_ips
    for i in range(nenvs):
        for j in range(nidss):
            vms.append(f'ids_{i}_{j}')
            ips.append(ips_i)
            sources.append(ids_sources)
            scripts.append(ids_script)
            mounts.append(None)
            ips_i = increment_ips(ips_i)

    vagrant_file_lines = vagrantfile_provider(mgmt_network=mgmt_network, storage_pool_name=args.storage)
    vagrant_file_lines.extend(vagrantfile_vms(vms, ips, sources, scripts, mounts))
    vagrant_file_lines.extend(vagrantfile_end())
    with open('Vagrantfile', 'w') as f:
        f.writelines(vagrant_file_lines)

    # download controller

    download_controller(version='0.12.3')

    # input directories

    m_dir = osp.join(classfier_models_dir, 'checkpoints')
    r_dir = osp.join(classfier_models_dir, 'results')

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

    # compile models

    model_names = [item for item in os.listdir(m_dir) if osp.isdir(osp.join(m_dir, item))]
    for model_name in model_names:
        spl = model_name.split('_')
        input_name = osp.join(m_dir, model_name)
        sstep = spl[-2]
        alabel = spl[-1]
        if alabel in label_names:
            output_name = osp.join(w_dir, '{0}_{1}.tflite'.format(sstep, alabel))
            converter = tf.lite.TFLiteConverter.from_saved_model(input_name)
            tflite_model = converter.convert()
            open(output_name, "wb").write(tflite_model)

    # select thresholds

    for label_name in non_zero_label_names:
        label_input = osp.join(r_dir, label_name)
        model_results = [osp.join(label_input, item) for item in os.listdir(label_input) if osp.isdir(osp.join(label_input, item))]
        for model_result in model_results:
            roc = pandas.read_csv(osp.join(model_result, 'roc.csv'), delimiter=' ', header=None).values
            thrs = []
            for fpr_level in fpr_levels:
                idx = np.where(roc[:, 0] <= fpr_level)[0][-1]
                thrs.append(str(roc[idx, 2]))
            spl = model_result.split('_')
            with open(osp.join(t_dir, '{0}.thr'.format('_'.join(spl[-2:]))), 'w') as f:
                f.write(','.join(thrs))

    # copy feature extraction functions to ids and ovs vms

    if not osp.isdir('{0}/common'.format(ids_sources_dir)):
        os.mkdir('{0}/common'.format(ids_sources_dir))
    shutil.copy('common/pcap.py', '{0}/common/'.format(ids_sources_dir))
    shutil.copy('common/data.py', '{0}/common/'.format(ids_sources_dir))

    if not osp.isdir('{0}/common'.format(ovs_sources_dir)):
        os.mkdir('{0}/common'.format(ovs_sources_dir))
    shutil.copy('common/pcap.py', '{0}/common/'.format(ovs_sources_dir))
    shutil.copy('common/data.py', '{0}/common/'.format(ovs_sources_dir))

    # copy meta for ids

    shutil.copy('{0}/metainfo.json'.format(feature_dir), ids_sources_dir)
