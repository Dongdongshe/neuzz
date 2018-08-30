import keras
import pickle
from keras.models import Sequential
from keras.layers import Dense, Dropout, Activation, Flatten, LeakyReLU
import os
import numpy as np
import glob
import ipdb
import random
import math
from keras.callbacks import ModelCheckpoint
import time
import keras.backend as K
import tensorflow as tf
from tensorflow import set_random_seed
import subprocess
from collections import Counter
import socket

HOST='127.0.0.1'
PORT=12012

MAX_FILE_SIZE = 10000
MAX_BITMAP_SIZE = 2000
#seed = int(time.time())
round_cnt=0
seed = 12
np.random.seed(seed)
random.seed(seed)
set_random_seed(seed)
seed_list = glob.glob('./seeds/*')
test_list = []
SPLIT_RATIO = len(seed_list)

# process training data from afl raw data
def process_data():
    global MAX_BITMAP_SIZE
    global MAX_FILE_SIZE
    global SPLIT_RATIO
    global seed_list

    # shuffle training samples
    seed_list = glob.glob('./seeds/*')
    seed_list.sort()
    SPLIT_RATIO = len(seed_list)
    rand_index = np.arange(SPLIT_RATIO)
    np.random.shuffle(seed_list)

    call=subprocess.check_output
    # get MAX_FILE_SIZE
    cwd = os.getcwd()
    max_file_name = call(['ls','-S', cwd+'/seeds/']).split('\n')[0].rstrip('\n')
    MAX_FILE_SIZE = os.path.getsize(cwd+'/seeds/'+max_file_name)
    # create bitmaps directory to save label
    if os.path.isdir("./bitmaps/") == False:
        os.makedirs('./bitmaps')
    # obtain raw bitmaps
    raw_bitmap = {}
    tmp_cnt = []
    for f in seed_list:
        tmp_list = []
        out = call(['afl-showmap', '-q', '-e', '-o', '/dev/stdout', './size', f])
        for line in out.splitlines():
            edge = line.split(':')[0]
            tmp_cnt.append(edge)
            tmp_list.append(edge)
        raw_bitmap[f] = tmp_list
    counter = Counter(tmp_cnt).most_common()
    # save bitmaps to individual numpy label
    label = [int(f[0]) for f in counter]
    bitmap = np.zeros((len(seed_list), len(label)))
    for idx,i in enumerate(seed_list):
        tmp = raw_bitmap[i]
        for j in tmp:
            if int(j) in label:
                bitmap[idx][label.index((int(j)))] = 1
    fit_bitmap = np.unique(bitmap,axis=1)
    print("data dimension" + str(fit_bitmap.shape))
    MAX_BITMAP_SIZE = fit_bitmap.shape[1]
    for idx,i in enumerate(seed_list):
        file_name = "./bitmaps/"+i.split('/')[-1]
        np.save(file_name,fit_bitmap[idx])


# training data generator
def generate_training_data(lb,ub):
    seed = np.zeros((ub-lb,MAX_FILE_SIZE))
    bitmap = np.zeros((ub-lb,MAX_BITMAP_SIZE))
    for i in range(lb,ub):
        tmp = open(seed_list[i],'r').read()
        ln = len(tmp)
        if ln < MAX_FILE_SIZE:
            tmp = tmp + (MAX_FILE_SIZE - ln) * '\0'
        seed[i-lb] = [ord(j) for j in list(tmp)]

    for i in range(lb,ub):
        file_name = "./bitmaps/"+ seed_list[i].split('/')[-1] + ".npy"
        bitmap[i-lb] = np.load(file_name)
    return seed,bitmap

# testing data generator
def generate_testing_data(lb,ub):
    seed = np.zeros((ub-lb,MAX_FILE_SIZE))
    bitmap = np.zeros((ub-lb,MAX_BITMAP_SIZE))
    for i in range(lb,ub):
        tmp = open(test_list[i],'r').read()
        if len(tmp) > MAX_FILE_SIZE:
            tmp=tmp[:7508]
        ln = len(tmp)
        if ln < MAX_FILE_SIZE:
            tmp = tmp + (MAX_FILE_SIZE - ln) * '\0'
        seed[i-lb] = [ord(j) for j in list(tmp)]
    for i in range(lb,ub):
        file_name = "/local/dongdong/to_go/new_fit_bitmaps/" + test_list[i].split('/')[-1] + ".npy"
        bitmap[i-lb] = np.load(file_name)
    return seed,bitmap

#learning rate decay
def step_decay(epoch):
    initial_lrate = 0.001
    drop = 0.7
    epochs_drop = 10.0
    lrate = initial_lrate * math.pow(drop,math.floor((1+epoch)/epochs_drop))
    return lrate

class LossHistory(keras.callbacks.Callback):
    def on_train_begin(self, logs={}):
        self.losses = []
        self.lr = []

    def on_epoch_end(self, batch, logs={}):
        self.losses.append(logs.get('loss'))
        self.lr.append(step_decay(len(self.losses)))
        print(step_decay(len(self.losses)))

#compute jaccard accuracy for multiple label
def accur_1(y_true,y_pred):
    y_true = tf.round(y_true)
    pred = tf.round(y_pred)
    summ = tf.constant(MAX_BITMAP_SIZE,dtype=tf.float32)
    wrong_num = tf.subtract(summ,tf.reduce_sum(tf.cast(tf.equal(y_true, pred),tf.float32),axis=-1))
    right_1_num = tf.reduce_sum(tf.cast(tf.logical_and(tf.cast(y_true,tf.bool), tf.cast(pred,tf.bool)),tf.float32),axis=-1)
    #summ_1 = tf.reduce_sum(tf.cast(y_true,tf.float32),axis=-1)
    ret = K.mean(tf.divide(right_1_num,tf.add(right_1_num,wrong_num)))
    return ret

def train_generate(batch_size):
    global seed_list
    while 1:
        np.random.shuffle(seed_list)
        for i in range(0,SPLIT_RATIO,batch_size):
            # create numpy arrays of input data
            # and labels, from each line in the file
            if (i+batch_size) > SPLIT_RATIO:
                x,y=generate_training_data(i,SPLIT_RATIO)
                #x = x.reshape((x.shape[0],x.shape[1],1)).astype('float32')/255
                x = x.astype('float32')/255
            else:
                x,y=generate_training_data(i,i+batch_size)
                #x = x.reshape((x.shape[0],x.shape[1],1)).astype('float32')/255
                x = x.astype('float32')/255
                #x = x_train[i:i+batch_size]
                #y = y_train[i:i+batch_size]
            yield (x,y)

def test_generate(batch_size):
    while 1:
        for i in range(0,len(test_list),batch_size):
            # create numpy arrays of input data
            # and labels, from each line in the file
            if (i+batch_size) > len(test_list):
                x,y=generate_testing_data(i,len(test_list))
                #x = x.reshape((x.shape[0],x.shape[1],1)).astype('float32')/255
                x = x.astype('float32')/255
                #x = x_train[i+10000:]
                #y = y_train[i+10000:]
            else:
                x,y=generate_testing_data(i,i+batch_size)
                #x = x.reshape((x.shape[0],x.shape[1],1)).astype('float32')/255
                x = x.astype('float32')/255
                #x = x_train[i+10000:i+batch_size+10000]
                #y = y_train[i+10000:i+batch_size+10000]
            yield (x,y)

# get vector representation of input
def vectorize_file(fl):
    seed = np.zeros((1,MAX_FILE_SIZE))
    tmp = open(fl,'r').read()
    ln = len(tmp)
    if ln < MAX_FILE_SIZE:
        tmp = tmp + (MAX_FILE_SIZE - ln) * '\0'
    seed[0] = [ord(j) for j in list(tmp)]
    seed = seed.astype('float32')/255
    return seed

def gen_adv2(f,fl,model,layer_list):
    adv_list = []
    loss = layer_list[-2][1].output[:,f]
    grads = K.gradients(loss,model.input)[0]
    #grads /= (K.sqrt(K.sum(K.square(grads))))
    iterate = K.function([model.input], [loss, grads])
    ll=2
    #fl= random.sample(xrange(SPLIT_RATIO),2)
    for index in range(ll):
        x=vectorize_file(fl[index])
        loss_value, grads_value = iterate([x])
        idx = np.flip(np.argsort(np.absolute(grads_value),axis=1)[:,-1024:].reshape((1024,)),0)
        val = np.sign(grads_value[0][idx])
        adv_list.append((idx,val,fl[index]))
    return adv_list


def gen_mutate2(model, edge_num):
    tmp_list = []
    # select seeds
    print("#######debug" + str(round_cnt))
    if(round_cnt == 0):
        new_seed_list = seed_list
    else:
        new_seed_list = glob.glob("./seeds/id_"+str(round_cnt-1)+"_*")
    if(len(new_seed_list) < (edge_num * 2)):
        rand_seed = random.sample(new_seed_list, len(new_seed_list))
        rand_seed.extend(random.sample(seed_list, (edge_num * 2 - len(new_seed_list))))
    else:
        rand_seed = random.sample(new_seed_list, edge_num * 2)
    # select output neurons to compute gradient
    interested_indice = np.random.choice(MAX_BITMAP_SIZE, edge_num)
    layer_list = [(layer.name, layer) for layer in model.layers]

    with open('gradient_info_p','w') as f:
        for idxx in range(len(interested_indice[:])):
            print("number of feature "+str(idxx))
            index = int(interested_indice[idxx])
            fl = rand_seed[idxx*2:idxx*2+2]
            adv_list = gen_adv2(index,fl,model,layer_list)
            tmp_list.append(adv_list)
            for ele in adv_list:
                ele0 = [str(el) for el in ele[0]]
                ele1 = [str(int(el)) for el in ele[1]]
                ele2 = ele[2]
                f.write(",".join(ele0)+'|'+",".join(ele1)+'|'+ele2+"\n")

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
              steps_per_epoch = (SPLIT_RATIO/16 + 1),
              epochs=100,
              verbose=1, callbacks=callbacks_list)
              #validation_data=test_generate(128),validation_steps=((len(test_list))/128+1))#,callbacks=[callback])
    # Save model and weights
    model.save_weights("hard_label.h5")

def gen_grad():
    global round_cnt
    t0=time.time()
    process_data()
    model = build_model()
    train(model)
    gen_mutate2(model, 300)
    round_cnt = round_cnt+1
    print(time.time()-t0)

def setup_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(1)
    conn, addr = sock.accept()
    print('connected by neuzz execution moduel'+str(addr))
    while True:
        data = conn.recv(1024)
        if not data: break
        else:
            gen_grad()
    conn.close()

gen_grad()
setup_server()
