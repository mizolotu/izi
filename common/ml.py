import os, json
import os.path as osp
import tensorflow as tf
import numpy as np

def load_batches(path, batch_size, nfeatures):
    batches = tf.data.experimental.make_csv_dataset(
        path,
        batch_size=batch_size,
        header=False,
        shuffle=True,
        column_names=[str(i) for i in range(nfeatures)],
        column_defaults=[tf.float32 for _ in range(nfeatures)],
        select_columns=[str(i) for i in range(nfeatures)],
        label_name='{0}'.format(nfeatures - 1),
    )
    return batches

def load_meta(fpath, fname='metainfo.json'):
    meta = None
    try:
        with open(osp.join(fpath, fname)) as f:
            meta = json.load(f)
    except Exception as e:
        print(e)
    return meta

def set_seeds(seed):
    tf.random.set_seed(seed)
    np.random.seed(seed)

def classification_mapper(features, label, xmin, xmax, eps=1e-10):
    features = (tf.stack(list(features.values()), axis=-1) - xmin) / (xmax - xmin + eps)
    label = tf.clip_by_value(label, 0, 1)
    return features, label

def mlp_comp(nfeatures, p1=[2], p2=[128,256,512,1024,2048], dropout=0.5, batchnorm=True, lr=5e-5):

    nlayers = p1
    nhidden = p2

    models = []
    model_names = []

    for nh in nhidden:
        for nl in nlayers:
            inputs = tf.keras.layers.Input(shape=(nfeatures - 1,))
            if batchnorm:
                hidden = tf.keras.layers.BatchNormalization()(inputs)
            else:
                hidden = inputs
            for _ in range(nl):
                hidden = tf.keras.layers.Dense(nh, activation='relu')(hidden)
                if dropout is not None:
                    hidden = tf.keras.layers.Dropout(dropout)(hidden)
            outputs = tf.keras.layers.Dense(1, activation='sigmoid')(hidden)
            model = tf.keras.models.Model(inputs=inputs, outputs=outputs)
            #model.compile(loss='binary_crossentropy', optimizer=tf.keras.optimizers.Adam(lr=lr), metrics=['accuracy'])
            model.compile(loss=tf.keras.losses.BinaryCrossentropy(), optimizer=tf.keras.optimizers.Adam(lr=lr), metrics=[tf.keras.metrics.AUC(name='auc'), 'binary_accuracy'])
            models.append(model)
            model_names.append('mlp_{0}_{1}'.format(nl, nh))
    return models, model_names

def mlp(nfeatures, nl, nh, dropout=0.5, batchnorm=True, lr=5e-5):
    inputs = tf.keras.layers.Input(shape=(nfeatures - 1,))
    if batchnorm:
        hidden = tf.keras.layers.BatchNormalization()(inputs)
    else:
        hidden = inputs
    for _ in range(nl):
        hidden = tf.keras.layers.Dense(nh, activation='relu')(hidden)
        if dropout is not None:
            hidden = tf.keras.layers.Dropout(dropout)(hidden)
    outputs = tf.keras.layers.Dense(1, activation='sigmoid')(hidden)
    model = tf.keras.models.Model(inputs=inputs, outputs=outputs)
    model.compile(loss=tf.keras.losses.BinaryCrossentropy(), optimizer=tf.keras.optimizers.Adam(lr=lr), metrics=[tf.keras.metrics.AUC(name='auc'), 'binary_accuracy'])
    return model, 'mlp_{0}_{1}'