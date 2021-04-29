import json
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

def load_batches_for_anomaly_detection(path, batch_size, nfeatures):
    batches = tf.data.experimental.make_csv_dataset(
        path,
        batch_size=batch_size,
        header=False,
        shuffle=True,
        column_names=[str(i) for i in range(nfeatures)],
        column_defaults=[tf.float32 for _ in range(nfeatures)],
        select_columns=[str(i) for i in range(nfeatures)]
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

def anomaly_detection_mapper(features, labels, xmin, xmax, eps=1e-10):
    features = (tf.stack(list(features.values()), axis=-1) - xmin) / (xmax - xmin + eps)
    features_with_labels = tf.concat([features, tf.reshape(labels, (-1, 1))], axis=1)
    return features, features_with_labels

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
    model.compile(loss=tf.keras.losses.BinaryCrossentropy(), optimizer=tf.keras.optimizers.Adam(lr=lr), metrics=[tf.keras.metrics.AUC(name='auc'), tf.keras.metrics.BinaryAccuracy(name='accuracy'), tf.keras.metrics.Precision(name='precision')])
    return model, 'mlp_{0}_{1}'.format(nh, nl)

def identity_block(x, nhidden):  # h = f(x) + x
    h = tf.keras.layers.Dense(nhidden)(x)
    h = tf.keras.layers.BatchNormalization()(h)
    h = tf.keras.layers.Add()([x, h])
    h = tf.keras.layers.Activation(activation='relu')(h)
    return h

def dense_block(x, nhidden):  # h = f(x) + g(x)
    h = tf.keras.layers.Dense(nhidden)(x)
    h = tf.keras.layers.BatchNormalization()(h)
    s = tf.keras.layers.Dense(nhidden)(x)
    s = tf.keras.layers.BatchNormalization()(s)
    h = tf.keras.layers.Add()([s, h])
    h = tf.keras.layers.Activation(activation='relu')(h)
    return h

def res(nfeatures, nb, nh, dropout=0.5, lr=5e-5):
    inputs = tf.keras.layers.Input(shape=(nfeatures - 1,))
    hidden = tf.keras.layers.Dense(nh)(inputs)
    for _ in range(nb):
        hidden = identity_block(hidden, nh)
        hidden = dense_block(hidden, nh)
        if dropout is not None:
            hidden = tf.keras.layers.Dropout(dropout)(hidden)
    outputs = tf.keras.layers.Dense(1, activation='sigmoid')(hidden)
    model = tf.keras.models.Model(inputs=inputs, outputs=outputs)
    model.compile(loss=tf.keras.losses.BinaryCrossentropy(), optimizer=tf.keras.optimizers.Adam(lr=lr), metrics=[tf.keras.metrics.AUC(name='auc'), 'binary_accuracy'])
    return model, 'resnet_{0}_{1}'.format(nb, nh)

def attention_block(x, nh):
    q = tf.keras.layers.Dense(nh, use_bias=False)(x)
    k = tf.keras.layers.Dense(nh, use_bias=False)(x)
    v = tf.keras.layers.Dense(nh, use_bias=False)(x)
    a = tf.keras.layers.Multiply()([q, k])
    a = tf.keras.layers.Softmax(axis=-1)(a)
    h = tf.keras.layers.Multiply()([a, v])
    return h

def att(nfeatures, nb, nh, dropout=0.5, batchnorm=True, lr=5e-5):
    inputs = tf.keras.layers.Input(shape=(nfeatures - 1,))
    if batchnorm:
        hidden = tf.keras.layers.BatchNormalization()(inputs)
    else:
        hidden = inputs
    for _ in range(nb):
        hidden = attention_block(hidden, nh)
        if dropout is not None:
            hidden = tf.keras.layers.Dropout(dropout)(hidden)
    outputs = tf.keras.layers.Dense(1, activation='sigmoid')(hidden)
    model = tf.keras.models.Model(inputs=inputs, outputs=outputs)
    model.compile(loss=tf.keras.losses.BinaryCrossentropy(), optimizer=tf.keras.optimizers.Adam(lr=lr), metrics=[tf.keras.metrics.AUC(name='auc'), 'binary_accuracy'])
    return model, 'attnet_{0}_{1}'.format(nb, nh)

def ae_reconstruction_loss(y_true, y_pred):
    y_true, _ = tf.split(y_true, [y_pred.shape[1], 1], axis=1)
    squared_difference = tf.square(y_true - y_pred)
    return tf.reduce_mean(squared_difference, axis=-1)

class ReconstructionAuc(tf.keras.metrics.AUC):

    def __init__(self, name='reconstruction_auc', **kwargs):
        super(ReconstructionAuc, self).__init__(name=name, **kwargs)

    def update_state(self, y_true, y_pred, sample_weight=None):
        y_true, label_true = tf.split(y_true, [y_pred.shape[1], 1], axis=1)
        label_true = tf.clip_by_value(label_true, 0, 1)
        reconstruction_error = tf.reduce_mean(tf.square(y_true - y_pred), axis=-1)
        super(ReconstructionAuc, self).update_state(label_true, reconstruction_error, sample_weight)

class ReconstructionPrecision(tf.keras.metrics.Metric):

    def __init__(self, name='reconstruction_precision', alpha=3, **kwargs):
        super(ReconstructionPrecision, self).__init__(name=name, **kwargs)
        self.alpha = alpha
        self.reconstruction_errors = tf.Variable([], shape=(None,), validate_shape=False)
        self.true_labels = tf.Variable([], shape=(None,), validate_shape=False)

    def update_state(self, y_true, y_pred, sample_weight=None):
        y_true, label_true = tf.split(y_true, [y_pred.shape[1], 1], axis=1)
        label_true = tf.clip_by_value(label_true, 0, 1)
        reconstruction_errors = tf.math.sqrt(tf.reduce_sum(tf.square(y_true - y_pred), axis=-1))
        self.reconstruction_errors.assign(tf.concat([self.reconstruction_errors.value(), reconstruction_errors], axis=0))
        self.true_labels.assign(tf.concat([self.true_labels.value(), label_true[:, 0]], axis=0))

    def result(self):
        thr = tf.reduce_mean(self.reconstruction_errors) + self.alpha * tf.math.reduce_std(self.reconstruction_errors)
        predictions = tf.math.greater_equal(self.reconstruction_errors, thr)
        true_labels = tf.cast(self.true_labels, tf.bool)
        true_positives = tf.logical_and(tf.equal(predictions, True), tf.equal(true_labels, True))
        true_positives = tf.cast(true_positives, self.dtype)
        false_positives = tf.logical_and(tf.equal(predictions, True), tf.equal(true_labels, False))
        false_positives = tf.cast(false_positives, self.dtype)
        return tf.reduce_sum(true_positives)  / (tf.reduce_sum(true_positives) + tf.reduce_sum(false_positives))

    def reset_states(self):
        self.reconstruction_errors.assign([])
        self.true_labels.assign([])

def ae(nfeatures, nl, nh, dropout=0.5, batchnorm=True, lr=5e-5):
    inputs = tf.keras.layers.Input(shape=(nfeatures - 1,))
    if batchnorm:
        norm = tf.keras.layers.BatchNormalization()
        hidden = norm(inputs)
    else:
        hidden = inputs
    for i in range(nl):
        hidden = tf.keras.layers.Dense(nh, activation='relu')(hidden)
        if dropout is not None:
            hidden = tf.keras.layers.Dropout(dropout)(hidden)
    for _ in range(nl):
        hidden = tf.keras.layers.Dense(nh, activation='relu')(hidden)
        if dropout is not None:
            hidden = tf.keras.layers.Dropout(dropout)(hidden)
        outputs = tf.keras.layers.Dense(nfeatures - 1, activation='sigmoid')(hidden)
        model = tf.keras.models.Model(inputs=inputs, outputs=outputs)
        model.compile(loss=ae_reconstruction_loss, optimizer=tf.keras.optimizers.Adam(lr=lr), metrics=ReconstructionPrecision(name='pre')) #, metrics=[tf.keras.metrics.MeanSquaredError(name='mse')])
    return model, 'ae_{0}_{1}'.format(nl, nh)
