#!/usr/bin/env python
# -*- coding: utf-8 -*-


import os
import sys
import glob
import math
import time
import keras
import random
import socket
import subprocess
import numpy as np
import tensorflow as tf
import keras.backend as K
from collections import Counter
from tensorflow import set_random_seed
from keras.models import Sequential
from keras.layers import Dense, Dropout, Activation
from keras.callbacks import ModelCheckpoint

HOST = '127.0.0.1'
PORT = 12012

MAX_FILE_SIZE = 10000
MAX_BITMAP_SIZE = 2000
round_cnt = 0
# Choose a seed for random initilzation
# seed = int(time.time())
seed = 12
np.random.seed(seed)
random.seed(seed)
set_random_seed(seed)
seed_list = glob.glob('./seeds/*')
new_seeds = glob.glob('./seeds/id_*')
SPLIT_RATIO = len(seed_list)
# get binary argv
argvv = sys.argv[1:]


# process training data from afl raw data
def process_data():
    global MAX_BITMAP_SIZE
    global MAX_FILE_SIZE
    global SPLIT_RATIO
    global seed_list
    global new_seeds

    # shuffle training samples
    seed_list = glob.glob('./seeds/*')
    seed_list.sort()
    SPLIT_RATIO = len(seed_list)
    rand_index = np.arange(SPLIT_RATIO)
    np.random.shuffle(seed_list)
    new_seeds = glob.glob('./seeds/id_*')

    call = subprocess.check_output

    # get MAX_FILE_SIZE
    cwd = os.getcwd()
    max_file_name = call(['ls', '-S', cwd + '/seeds/']).decode('utf8').split('\n')[0].rstrip('\n')
    MAX_FILE_SIZE = os.path.getsize(cwd + '/seeds/' + max_file_name)

    # create directories to save label, spliced seeds, variant length seeds, crashes and mutated seeds.
    os.path.isdir("./bitmaps/") or os.makedirs("./bitmaps")
    os.path.isdir("./splice_seeds/") or os.makedirs("./splice_seeds")
    os.path.isdir("./vari_seeds/") or os.makedirs("./vari_seeds")
    os.path.isdir("./crashes/") or os.makedirs("./crashes")

    # obtain raw bitmaps
    raw_bitmap = {}
    tmp_cnt = []
    out = ''
    for f in seed_list:
        tmp_list = []
        try:
            # append "-o tmp_file" to strip's arguments to avoid tampering tested binary.
            if argvv[0] == './strip':
                out = call(['./afl-showmap', '-q', '-e', '-o', '/dev/stdout', '-m', '512', '-t', '500'] + argvv + [f] + ['-o', 'tmp_file'])
            else:
                out = call(['./afl-showmap', '-q', '-e', '-o', '/dev/stdout', '-m', '512', '-t', '500'] + argvv + [f])
        except subprocess.CalledProcessError:
            print("find a crash")
        for line in out.splitlines():
            edge = line.split(b':')[0]
            tmp_cnt.append(edge)
            tmp_list.append(edge)
        raw_bitmap[f] = tmp_list
    counter = Counter(tmp_cnt).most_common()

    # save bitmaps to individual numpy label
    label = [int(f[0]) for f in counter]
    bitmap = np.zeros((len(seed_list), len(label)))
    for idx, i in enumerate(seed_list):
        tmp = raw_bitmap[i]
        for j in tmp:
            if int(j) in label:
                bitmap[idx][label.index((int(j)))] = 1

    # label dimension reduction
    fit_bitmap = np.unique(bitmap, axis=1)
    print("data dimension" + str(fit_bitmap.shape))

    # save training data
    MAX_BITMAP_SIZE = fit_bitmap.shape[1]
    for idx, i in enumerate(seed_list):
        file_name = "./bitmaps/" + i.split('/')[-1]
        np.save(file_name, fit_bitmap[idx])


# training data generator
def generate_training_data(lb, ub):
    seed = np.zeros((ub - lb, MAX_FILE_SIZE))
    bitmap = np.zeros((ub - lb, MAX_BITMAP_SIZE))
    for i in range(lb, ub):
        tmp = open(seed_list[i], 'rb').read()
        ln = len(tmp)
        if ln < MAX_FILE_SIZE:
            tmp = tmp + (MAX_FILE_SIZE - ln) * b'\x00'
        seed[i - lb] = [j for j in bytearray(tmp)]

    for i in range(lb, ub):
        file_name = "./bitmaps/" + seed_list[i].split('/')[-1] + ".npy"
        bitmap[i - lb] = np.load(file_name)
    return seed, bitmap


# learning rate decay
def step_decay(epoch):
    initial_lrate = 0.001
    drop = 0.7
    epochs_drop = 10.0
    lrate = initial_lrate * math.pow(drop, math.floor((1 + epoch) / epochs_drop))
    return lrate


class LossHistory(keras.callbacks.Callback):

    def on_train_begin(self, logs={}):
        self.losses = []
        self.lr = []

    def on_epoch_end(self, batch, logs={}):
        self.losses.append(logs.get('loss'))
        self.lr.append(step_decay(len(self.losses)))
        print(step_decay(len(self.losses)))


# compute jaccard accuracy for multiple label
def accur_1(y_true, y_pred):
    y_true = tf.round(y_true)
    pred = tf.round(y_pred)
    summ = tf.constant(MAX_BITMAP_SIZE, dtype=tf.float32)
    wrong_num = tf.subtract(summ, tf.reduce_sum(tf.cast(tf.equal(y_true, pred), tf.float32), axis=-1))
    right_1_num = tf.reduce_sum(tf.cast(tf.logical_and(tf.cast(y_true, tf.bool), tf.cast(pred, tf.bool)), tf.float32), axis=-1)
    return K.mean(tf.divide(right_1_num, tf.add(right_1_num, wrong_num)))


def train_generate(batch_size):
    global seed_list
    while 1:
        np.random.shuffle(seed_list)
        # load a batch of training data
        for i in range(0, SPLIT_RATIO, batch_size):
            # load full batch
            if (i + batch_size) > SPLIT_RATIO:
                x, y = generate_training_data(i, SPLIT_RATIO)
                x = x.astype('float32') / 255
            # load remaining data for last batch
            else:
                x, y = generate_training_data(i, i + batch_size)
                x = x.astype('float32') / 255
            yield (x, y)


# get vector representation of input
def vectorize_file(fl):
    seed = np.zeros((1, MAX_FILE_SIZE))
    tmp = open(fl, 'rb').read()
    ln = len(tmp)
    if ln < MAX_FILE_SIZE:
        tmp = tmp + (MAX_FILE_SIZE - ln) * b'\x00'
    seed[0] = [j for j in bytearray(tmp)]
    seed = seed.astype('float32') / 255
    return seed


# splice two seeds to a new seed
def splice_seed(fl1, fl2, idxx):
    tmp1 = open(fl1, 'rb').read()
    ret = 1
    randd = fl2
    while ret == 1:
        tmp2 = open(randd, 'rb').read()
        if len(tmp1) >= len(tmp2):
            lenn = len(tmp2)
            head = tmp2
            tail = tmp1
        else:
            lenn = len(tmp1)
            head = tmp1
            tail = tmp2
        f_diff = 0
        l_diff = 0
        for i in range(lenn):
            if tmp1[i] != tmp2[i]:
                f_diff = i
                break
        for i in reversed(range(lenn)):
            if tmp1[i] != tmp2[i]:
                l_diff = i
                break
        if f_diff >= 0 and l_diff > 0 and (l_diff - f_diff) >= 2:
            splice_at = f_diff + random.randint(1, l_diff - f_diff - 1)
            head = list(head)
            tail = list(tail)
            tail[:splice_at] = head[:splice_at]
            with open('./splice_seeds/tmp_' + str(idxx), 'wb') as f:
                f.write(bytearray(tail))
            ret = 0
        print(f_diff, l_diff)
        randd = random.choice(seed_list)


# compute gradient for given input
def gen_adv2(f, fl, model, layer_list, idxx, splice):
    adv_list = []
    loss = layer_list[-2][1].output[:, f]
    grads = K.gradients(loss, model.input)[0]
    iterate = K.function([model.input], [loss, grads])
    ll = 2
    while fl[0] == fl[1]:
        fl[1] = random.choice(seed_list)

    for index in range(ll):
        x = vectorize_file(fl[index])
        loss_value, grads_value = iterate([x])
        idx = np.flip(np.argsort(np.absolute(grads_value), axis=1)[:, -MAX_FILE_SIZE:].reshape((MAX_FILE_SIZE,)), 0)
        val = np.sign(grads_value[0][idx])
        adv_list.append((idx, val, fl[index]))

    # do not generate spliced seed for the first round
    if splice == 1 and round_cnt != 0:
        if round_cnt % 2 == 0:
            splice_seed(fl[0], fl[1], idxx)
            x = vectorize_file('./splice_seeds/tmp_' + str(idxx))
            loss_value, grads_value = iterate([x])
            idx = np.flip(np.argsort(np.absolute(grads_value), axis=1)[:, -MAX_FILE_SIZE:].reshape((MAX_FILE_SIZE,)), 0)
            val = np.sign(grads_value[0][idx])
            adv_list.append((idx, val, './splice_seeds/tmp_' + str(idxx)))
        else:
            splice_seed(fl[0], fl[1], idxx + 500)
            x = vectorize_file('./splice_seeds/tmp_' + str(idxx + 500))
            loss_value, grads_value = iterate([x])
            idx = np.flip(np.argsort(np.absolute(grads_value), axis=1)[:, -MAX_FILE_SIZE:].reshape((MAX_FILE_SIZE,)), 0)
            val = np.sign(grads_value[0][idx])
            adv_list.append((idx, val, './splice_seeds/tmp_' + str(idxx + 500)))

    return adv_list


# compute gradient for given input without sign
def gen_adv3(f, fl, model, layer_list, idxx, splice):
    adv_list = []
    loss = layer_list[-2][1].output[:, f]
    grads = K.gradients(loss, model.input)[0]
    iterate = K.function([model.input], [loss, grads])
    ll = 2
    while fl[0] == fl[1]:
        fl[1] = random.choice(seed_list)

    for index in range(ll):
        x = vectorize_file(fl[index])
        loss_value, grads_value = iterate([x])
        idx = np.flip(np.argsort(np.absolute(grads_value), axis=1)[:, -MAX_FILE_SIZE:].reshape((MAX_FILE_SIZE,)), 0)
        #val = np.sign(grads_value[0][idx])
        val = np.random.choice([1, -1], MAX_FILE_SIZE, replace=True)
        adv_list.append((idx, val, fl[index]))

    # do not generate spliced seed for the first round
    if splice == 1 and round_cnt != 0:
        splice_seed(fl[0], fl[1], idxx)
        x = vectorize_file('./splice_seeds/tmp_' + str(idxx))
        loss_value, grads_value = iterate([x])
        idx = np.flip(np.argsort(np.absolute(grads_value), axis=1)[:, -MAX_FILE_SIZE:].reshape((MAX_FILE_SIZE,)), 0)
        # val = np.sign(grads_value[0][idx])
        val = np.random.choice([1, -1], MAX_FILE_SIZE, replace=True)
        adv_list.append((idx, val, './splice_seeds/tmp_' + str(idxx)))

    return adv_list


# grenerate gradient information to guide furture muatation
def gen_mutate2(model, edge_num, sign):
    tmp_list = []
    # select seeds
    print("#######debug" + str(round_cnt))
    if round_cnt == 0:
        new_seed_list = seed_list
    else:
        new_seed_list = new_seeds

    if len(new_seed_list) < edge_num:
        rand_seed1 = [new_seed_list[i] for i in np.random.choice(len(new_seed_list), edge_num, replace=True)]
    else:
        rand_seed1 = [new_seed_list[i] for i in np.random.choice(len(new_seed_list), edge_num, replace=False)]
    if len(new_seed_list) < edge_num:
        rand_seed2 = [seed_list[i] for i in np.random.choice(len(seed_list), edge_num, replace=True)]
    else:
        rand_seed2 = [seed_list[i] for i in np.random.choice(len(seed_list), edge_num, replace=False)]

    # function pointer for gradient computation
    fn = gen_adv2 if sign else gen_adv3

    # select output neurons to compute gradient
    interested_indice = np.random.choice(MAX_BITMAP_SIZE, edge_num)
    layer_list = [(layer.name, layer) for layer in model.layers]

    with open('gradient_info_p', 'w') as f:
        for idxx in range(len(interested_indice[:])):
            # kears's would stall after multiple gradient compuation. Release memory and reload model to fix it.
            if idxx % 100 == 0:
                del model
                K.clear_session()
                model = build_model()
                model.load_weights('hard_label.h5')
                layer_list = [(layer.name, layer) for layer in model.layers]

            print("number of feature " + str(idxx))
            index = int(interested_indice[idxx])
            fl = [rand_seed1[idxx], rand_seed2[idxx]]
            adv_list = fn(index, fl, model, layer_list, idxx, 1)
            tmp_list.append(adv_list)
            for ele in adv_list:
                ele0 = [str(el) for el in ele[0]]
                ele1 = [str(int(el)) for el in ele[1]]
                ele2 = ele[2]
                f.write(",".join(ele0) + '|' + ",".join(ele1) + '|' + ele2 + "\n")


def build_model():
    batch_size = 32
    num_classes = MAX_BITMAP_SIZE
    epochs = 50

    model = Sequential()
    model.add(Dense(4096, input_dim=MAX_FILE_SIZE))
    model.add(Activation('relu'))
    model.add(Dense(num_classes))
    model.add(Activation('sigmoid'))

    opt = keras.optimizers.adam(lr=0.0001)

    model.compile(loss='binary_crossentropy', optimizer=opt, metrics=[accur_1])
    model.summary()

    return model


def train(model):
    loss_history = LossHistory()
    lrate = keras.callbacks.LearningRateScheduler(step_decay)
    callbacks_list = [loss_history, lrate]
    model.fit_generator(train_generate(16),
                        steps_per_epoch=(SPLIT_RATIO / 16 + 1),
                        epochs=100,
                        verbose=1, callbacks=callbacks_list)
    # Save model and weights
    model.save_weights("hard_label.h5")


def gen_grad(data):
    global round_cnt
    t0 = time.time()
    process_data()
    model = build_model()
    train(model)
    # model.load_weights('hard_label.h5')
    gen_mutate2(model, 500, data[:5] == b"train")
    round_cnt = round_cnt + 1
    print(time.time() - t0)


def setup_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(1)
    conn, addr = sock.accept()
    print('connected by neuzz execution moduel ' + str(addr))
    gen_grad(b"train")
    conn.sendall(b"start")
    while True:
        data = conn.recv(1024)
        if not data:
            break
        else:
            gen_grad(data)
            conn.sendall(b"start")
    conn.close()


if __name__ == '__main__':
    setup_server()
