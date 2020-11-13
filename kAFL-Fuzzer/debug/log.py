# Implemented functions for debugging and logging
#
# Written by Juhyun Song

EXCEPT_PREFIX = '\033[1;31m[EXCEPT]\033[0m '
ERROR_PREFIX = '\033[1;31m[EXCEPT]\033[0m '
FLOW_PREFIX = '\033[1;31m[FLOW]\033[0m '
WARN_PREFIX = '\033[1;31m[WARNING]\033[0m '
KAFL_PREFIX = '\033[1;34m[KAFL]\033[0m '
INFO_PREFIX = '\033[1;32m[INFO]\033[0m '
YELLOW_PREFIX = '\033[1;33m[DEBUG]\033[0m '

ENABLE_LOG = True

def disable_log():
    global ENABLE_LOG
    ENABLE_LOG = False

def debug_info(msg):
    data = INFO_PREFIX + msg
    if ENABLE_LOG == True:
        print(data)

def debug_kafl(msg, newline=False):
    if newline:
        data = '\n' + KAFL_PREFIX + msg
    else:
        data = KAFL_PREFIX + msg
    if ENABLE_LOG == True:
        print(data)

def debug_warn(msg):
    data = WARN_PREFIX + msg
    if ENABLE_LOG == True:
        print(data)

def debug_error(msg):
    data = ERROR_PREFIX + msg
    if ENABLE_LOG == True:
        print(data)

def debug_except(msg):
    data = EXCEPT_PREFIX + msg
    if ENABLE_LOG == True:
        print(data)

def debug(msg, newline=False):
    if newline:
        data = '\n' + YELLOW_PREFIX + msg
    else:
        data = YELLOW_PREFIX + msg
    if ENABLE_LOG == True:
        print(data)