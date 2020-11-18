# Copyright 2017-2019 Sergej Schumilo, Cornelius Aschermann, Tim Blazytko
# Copyright 2019-2020 Intel Corporation
#
# SPDX-License-Identifier: AGPL-3.0-or-later

"""
Flitering logic for Interface-recoverd wdm drivers.
"""

import json
from common.util import atomic_write

class InterfaceRecoveryFilter:
    def __init__(self, config):
        wdm_file = config.argument_values['wdm']
        self.constraints = self.create_constraints(wdm_file)
        self.filter_threshold = None
        self.saving_index = 0

    def create_constraints(self, wdm_file):
        with open(wdm_file, 'r') as f:
            constraints = json.load(f)
        
        for i in constraints:
            in_buf_range = i['InputBufferLength'][0].split('-')
            in_buf_min = in_buf_range[0]
            in_buf_max = in_buf_range[1]
            if bool(in_buf_min == in_buf_max) == True:
                is_static = True
            else:
                is_static = False

            if in_buf_max == 'inf': 
                in_buf_max = 0xff # TODO determine inf size
            i['InputBufferLength'] = int(in_buf_max)

            del(i['OutputBufferLength'])

            i['isStatic'] = is_static
        return constraints
    
    def filter_payload(self, payload):
        i = 0
        decode_len = 0
        while(i < len(payload)):
            cIndex = payload[i]
            if cIndex >= len(self.constraints):
                break
            decode_len += 1
            i += self.constraints[cIndex]['InputBufferLength'] + 1
            if i > len(payload) and self.constraints[cIndex]['isStatic'] == True:
                break
        
        if self.filter_threshold == None:
            self.filter_threshold = decode_len
            return True
        else:
            if decode_len < self.filter_threshold - 2:
                return False
            else:
                return True
        return decode_len