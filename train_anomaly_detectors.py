import os
import os.path as osp
import argparse as arp
import numpy as np
import tensorflow as tf
import common.ml as models

from time import time
from sklearn.metrics import roc_curve
from sklearn.metrics import roc_auc_score
from common.ml import set_seeds, load_batches, anomaly_detection_mapper, load_meta, EarlyStoppingAtMaxAuc, ae_reconstruction_loss
from config import *

if __name__ == '__main__':

    parser = arp.ArgumentParser(description='Train classifiers')
    parser.add_argument('-m', '--model', help='Model', default='som')
    parser.add_argument('-l', '--layers', help='Number of layers', default=0, type=int)
    parser.add_argument('-n', '--neurons', help='Number of neurons', default=512, type=int)
    parser.add_argument('-a', '--attacks', help='Attack labels', nargs='+', default=['2,3,4', '1,3,4', '1,2,4', '1,2,3'])
    parser.add_argument('-s', '--steps', help='Polling step', nargs='+', default=['0.5', '1.0', '2.0', '4.0'])
    parser.add_argument('-c', '--cuda', help='Use CUDA', default=False, type=bool)
    args = parser.parse_args()

    if not args.cuda:
        os.environ["CUDA_VISIBLE_DEVICES"] = "-1"

    # global params

    num_batches = {
        'train': None,
        'validate': steps_per_epoch,
        'test': steps_per_epoch,
    }

    num_epochs = {
        'train': None,
        'validate': 1,
        'test': 1
    }

    # set seed for results reproduction

    if seed is not None:
        set_seeds(seed)

    # meta and labels

    meta = load_meta(feature_dir)
    labels = sorted(meta['labels'])

    for attack in args.attacks:

        if ',' in attack:
            attacks = [int(item) for item in attack.split(',') if item != '0']
        elif attack == '0':
            attacks = list(labels[1:])
        else:
            attacks = [int(attack)]
        attacks = sorted(attacks)
        train_labels = [0] + [label for label in labels if label in attacks]
        non_train_labels = [label for label in labels if label > 0 and label not in attacks]
        attack_labels_str = [str(item) for item in train_labels if item > 0]

        print(f'Training using attack labels {train_labels}')

        # batch_sizes

        batch_sizes = [batch_size] + [int(1.0 / (len(train_labels) - 1) * batch_size) for _ in train_labels[1:]]

        # fpath

        fpaths = [osp.join(feature_dir, str(int(label))) for label in train_labels]
        fpaths_label = {}
        for label in labels:
            if label > 0:
                fpaths_label[label] = [
                    osp.join(feature_dir, '0'),
                    osp.join(feature_dir, str(int(label)))
                ]

        # create output directories

        if not osp.isdir(ids_models_dir):
            os.mkdir(ids_models_dir)

        models_path = osp.join(ids_models_dir, 'checkpoints')
        if not osp.isdir(models_path):
            os.mkdir(models_path)

        results_path = osp.join(ids_models_dir, 'results')
        if not osp.isdir(results_path):
            os.mkdir(results_path)

        foutput = {}
        for label in non_train_labels:
            foutput[label] = osp.join(results_path, str(int(label)))
            if not osp.isdir(foutput[label]):
                os.mkdir(foutput[label])

        for step in args.steps:

            # input fpath

            fpaths_star = {}
            fpaths_star['train'] = [osp.join(fpaths[0], '*_{0}_{1}'.format(step, 'train'))]
            fpaths_star['validate'] = [osp.join(fpath, '*_{0}_{1}'.format(step, 'validate')) for fpath in fpaths]
            fpaths_star['test'] = {}
            for label in labels:
                if label > 0:
                    fpaths_star['test'][label] = [osp.join(fpath, f'*_{step}_test') for fpath in fpaths_label[label]]
                else:
                    fpaths_star['test'][label] = [osp.join(fpath, f'*_{step}_test') for fpath in fpaths]

            # meta

            nfeatures = meta['nfeatures']
            xmin = np.array(meta['xmin'])
            xmax = np.array(meta['xmax'])

            # mappers

            ad_mapper = lambda x, y: anomaly_detection_mapper(x, y, xmin=xmin, xmax=xmax)

            batches = {}

            batches_ = [load_batches(fp, bs, nfeatures).map(ad_mapper) for fp, bs in zip(fpaths_star['train'], batch_sizes)]
            batches['train'] = tf.data.experimental.sample_from_datasets(batches_, [1.0]).unbatch().shuffle(batch_size * 2).batch(batch_size)
            if num_batches['train'] is not None:
                batches['train'] = batches['train'].take(num_batches['train'])

            batches_ = [load_batches(fp, bs, nfeatures).map(ad_mapper) for fp, bs in zip(fpaths_star['validate'], batch_sizes)]
            batches['validate'] = tf.data.experimental.sample_from_datasets(batches_, [0.5] + [0.5 / (len(train_labels) - 1) for _ in train_labels[1:]]).unbatch().shuffle(batch_size * 2).batch(batch_size)
            if num_batches['validate'] is not None:
                batches['validate'] = batches['validate'].take(num_batches['validate'])

            batches['test'] = {}
            for label in non_train_labels:
                batches_ = [load_batches(fp, batch_size, nfeatures).map(ad_mapper) for fp in fpaths_star['test'][label]]
                batches['test'][label] = tf.data.experimental.sample_from_datasets([batches_[0], batches_[1]], [0.5, 0.5]).unbatch().shuffle(batch_size * 2).batch(batch_size)
                if num_batches['test'] is not None:
                    batches['test'][label] = batches['test'][label].take(num_batches['test'])

            model_type = getattr(models, args.model)
            model, model_name = model_type(nfeatures, args.layers, args.neurons)
            print('Training {0}'.format(model_name))
            model.summary()

            # create model checkpoint directories

            m_path = osp.join(models_path, f'{model_name}_{attack}_{step}')
            if not osp.isdir(m_path):
                os.mkdir(m_path)

            # load model

            try:
                model = tf.keras.models.load_model(m_path, compile=False)

            except Exception as e:
                print(e)

                # fit the model

                model.fit(
                    batches['train'],
                    validation_data=batches['validate'],
                    epochs=epochs,
                    steps_per_epoch=steps_per_epoch,
                    callbacks=[EarlyStoppingAtMaxAuc(validation_data=batches['validate'], model_type=args.model)]
                )

                # save model

                model.save(m_path)

            # calculate thresholds for fpr levels specified in config

            errors = []
            testy = []
            thrs = []
            for x, y in batches['validate']:
                reconstructions = model.predict(x)
                if args.model == 'ae':
                    new_errors = np.linalg.norm(reconstructions - y[:, :-1], axis=1)
                elif args.model == 'som':
                    new_errors = reconstructions
                errors = np.concatenate([errors, new_errors])
                testy = np.concatenate([testy, y[:, -1]])
            ns_fpr, ns_tpr, ns_thr = roc_curve(testy, errors)
            for fpr_level in fpr_levels:
                idx = np.where(ns_fpr <= fpr_level)[0][-1]
                thrs.append(str(ns_thr[idx]))
                print(ns_fpr[idx], ns_tpr[idx], ns_thr[idx])

            # save threshold

            open(osp.join(m_path, 'thr'), 'w').write(','.join(thrs))

            # predict and calculate inference statistics

            for label in non_train_labels:
                t_test = 0
                probs = []
                testy = []
                for x, y in batches['test'][label]:
                    y_labels = y[:, -1]
                    t_now = time()
                    reconstructions = model.predict(x)
                    if args.model == 'ae':
                        new_probs = np.linalg.norm(reconstructions - y[:, :-1], axis=1)
                    elif args.model == 'som':
                        new_probs = reconstructions
                    probs = np.hstack([probs, new_probs])
                    testy = np.hstack([testy, y_labels])
                    t_test += (time() - t_now)

                sk_auc = roc_auc_score(testy, probs)
                ns_fpr, ns_tpr, ns_thr = roc_curve(testy, probs)
                roc = np.zeros((ns_fpr.shape[0], 3))
                roc[:, 0] = ns_fpr
                roc[:, 1] = ns_tpr
                roc[:, 2] = ns_thr

                # save the results

                results = [str(sk_auc)]
                r_path = osp.join(foutput[label], f'{model_name}_{attack}_{step}')
                if not osp.isdir(r_path):
                    os.mkdir(r_path)
                stats_path = osp.join(r_path, 'stats.csv')
                roc_path = osp.join(r_path, 'roc.csv')
                with open(stats_path, 'w') as f:
                    f.write(','.join(results))
                np.savetxt(roc_path, roc)
