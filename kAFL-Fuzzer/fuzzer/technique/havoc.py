# Copyright (C) 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright (C) 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
AFL-style havoc and splicing stage 
"""

import glob

from common.config import FuzzerConfiguration
from fuzzer.technique.havoc_handler import *

SPLICE_ROUND = 2
HAVOC_MAX_LEN = 0xff

def load_dict(file_name):
    f = open(file_name)
    dict_entries = []
    for line in f:
        if not line.startswith("#"):
            try:
                dict_entries.append((line.split("=\"")[1].split("\"\n")[0]).decode("string_escape"))
            except:
                pass
    f.close()
    return dict_entries


def init_havoc(config):
    global location_corpus
    if config.argument_values["dict"]:
        set_dict(load_dict(FuzzerConfiguration().argument_values["dict"]))
    # AFL havoc adds these at runtime as soon as available dicts are non-empty
    if config.argument_values["dict"] or config.argument_values["redqueen"]:
        append_handler(havoc_dict_insert)
        append_handler(havoc_dict_replace)

    location_corpus = config.argument_values['work_dir'] + "/corpus/"


def havoc_range(perf_score):
    max_iterations = int(2*perf_score)

    if max_iterations < AFL_HAVOC_MIN:
        max_iterations = AFL_HAVOC_MIN

    return max_iterations


def mutate_seq_havoc_array(data, func, max_iterations, resize=False, splice=None):    
    if resize:
        data = data + data
    else:
        data = data

    # handling havoc
    if not splice:
        for i in range(max_iterations):
            stacking = rand.int(AFL_HAVOC_STACK_POW2)

            for j in range(1 << (1 + stacking)):
                handler = rand.select(havoc_handler)
                data = handler(data)
                if len(data) >= KAFL_MAX_FILE:
                    data = data[:KAFL_MAX_FILE]

            if len(data) >= HAVOC_MAX_LEN:
                data = data[:HAVOC_MAX_LEN]
            
            func(data)
    
    # handling splice
    else:
        state = 'splice'
        
        for i in range(max_iterations):
            newdata = ''
            for j in range(SPLICE_ROUND):
                handler = rand.select(havoc_handler)
                while len(newdata) <= (len(data) // 2):
                    newdata = handler(data)
                
                # test - havoc it again
                newdata = handler(newdata)

                if len(newdata) >= KAFL_MAX_FILE:
                    newdata = newdata[:KAFL_MAX_FILE]

            if len(newdata) >= HAVOC_MAX_LEN:
                newdata = newdata[:HAVOC_MAX_LEN]
            
            func(newdata)


def mutate_seq_splice_array(data, func, max_iterations, resize=False):
    global location_corpus
    splice_rounds = 16
    files = glob.glob(location_corpus + "/regular/payload_*")
    for _ in range(splice_rounds):
        spliced_data = havoc_splicing(data, files)
        if spliced_data is None:
            return # could not find any suitable splice pair for this file
        mutate_seq_havoc_array(spliced_data,
                               func,
                               int(2*max_iterations/splice_rounds),
                               resize=resize,
                               splice=True)
