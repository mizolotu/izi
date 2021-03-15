import os, pandas, shutil
import os.path as osp
import numpy as np
import tensorflow as tf

from common.utils import download_controller, clean_dir
from common.ml import load_meta
from config import *

if __name__ == '__main__':

    # clean logs

    clean_dir(log_dir, postfix='.json')

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

    # label names

    meta = load_meta(feature_dir)
    label_names = [str(item) for item in sorted(meta['labels']) if item > 0]

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

    #label_names = [item for item in os.listdir(r_dir) if osp.isdir(osp.join(r_dir, item))]
    for label_name in label_names:
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

    # copy feature extraction functions

    if not osp.isdir('{0}/common'.format(ids_sources_dir)):
        os.mkdir('{0}/common'.format(ids_sources_dir))
    shutil.copy('common/pcap.py', '{0}/common/'.format(ids_sources_dir))
    shutil.copy('common/data.py', '{0}/common/'.format(ids_sources_dir))

    # copy meta

    shutil.copy('{0}/metainfo.json'.format(feature_dir), ids_sources_dir)
