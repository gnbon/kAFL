import os
import sys
import signal
import time
import glob
import random
import psutil
import curses
import msgpack
import inotify.adapters
from threading import Thread, Lock

from common.util import read_binary_file
from kafl_fuzz import PAYQ

WORKDIR = ''
SVCNAME = ''

# current payload
PAYLOAD = ''

# screen width
WIDTH = 80

# color pair code
WHITE = 1
RED = 2
GREEN = 3
YELLOW = 4
BLUE = 5
MAGENTA = 6
CYAN = 7

BOLD = curses.A_BOLD
DIM = curses.A_DIM

def sigint_handler(sig, frame):
    curses.endwin()
    sys.exit(0)

# helper function for color pairs
def color(code):
    return curses.color_pair(code)

# helper function for formatting number
def pnum(num):
    assert num >= 0
    if num <= 9999:
        return "%d" % num
    num /= 1000.0
    if num <= 999:
        return "%.1fk" % num
    num /= 1000.0
    if num <= 999:
        return "%.1fm" % num
    num /= 1000.0
    if num <= 999:
        return "%.1fg" % num
    num /= 1000.0
    if num <= 999:
        return "%.1ft" % num
    num /= 1000.0
    if num <= 999:
        return "%.1fp" % num
    assert False

def pfloat(flt):
    assert flt >= 0
    if flt <= 999:
        return "%.1f" % flt
    return pnum(flt)

def pbyte(num):
    assert num >= 0
    if num <= 999:
        return "%d" % num
    num /= 1024.0
    if num <= 999:
        return "%.1fk" % num
    num /= 1024.0
    if num <= 999:
        return "%.1fm" % num
    num /= 1024.0
    if num <= 999:
        return "%.1fg" % num
    num /= 1024.0
    if num <= 999:
        return "%.1ft" % num
    num /= 1024.0
    if num <= 999:
        return "%.1fp" % num
    assert False

# helper function for formatting timestamps
def ptime(secs):
    if not secs:
        return "none yet"

    secs = int(secs)
    seconds = secs % 60
    secs //= 60
    mins = secs % 60
    secs //= 60
    hours = secs % 24
    days = secs  // 24
    return "%d days, %d hrs, %d min, %d sec" % (days, hours, mins, seconds)


class MonitorInterface:
    def __init__(self, stdscr):
        self.stdscr = stdscr
        self.y = 0

    def print_title(self):
        self.y += 1

        title1 = 'kAFL '
        title2 = f'({SVCNAME})'
        title3 = '2020 KITRI Best of the Best'
        center_len = len(title1) + len(title2)
        pad_len1 = (WIDTH - center_len) // 2
        pad_len2 = (WIDTH - len(title3)) // 2
        pad1 = ' ' * pad_len1
        pad2 = ' ' * pad_len2

        x = 0
        self.stdscr.addstr(self.y, x, pad1, BOLD)
        x += pad_len1
        self.stdscr.addstr(self.y, x, title1, color(YELLOW) + BOLD)
        x += len(title1)
        self.stdscr.addstr(self.y, x, title2, color(GREEN) + BOLD)
        x += len(title2)
        self.stdscr.addstr(self.y, x, pad1, BOLD)
        self.y += 1

        x = 0
        self.stdscr.addstr(self.y, x, pad2, BOLD)
        x += pad_len2
        self.stdscr.addstr(self.y, x, title3, color(CYAN) + BOLD)
        self.y += 2

    def print_guest_and_overall(self):
        self.stdscr.addstr(self.y, 0, '┌─', DIM)
        self.stdscr.addstr(self.y, 2, ' guest timing ', color(CYAN))
        self.stdscr.addstr(self.y, 16, '─'*37 + '┬─', DIM)
        self.stdscr.addstr(self.y, 55, ' overall results ', color(CYAN))
        self.stdscr.addstr(self.y, 72, '─'*7 + '┐', DIM)
        self.y += 1

    def print_execution_and_map(self):
        self.stdscr.addstr(self.y, 0, '├─', DIM)
        self.stdscr.addstr(self.y, 2, ' execution progress ', color(CYAN))
        self.stdscr.addstr(self.y, 22, '─'*14 + '┬─', DIM)
        self.stdscr.addstr(self.y, 38, ' map coverage ', color(CYAN))
        self.stdscr.addstr(self.y, 52,  '─┴'+ '─'*25 + '┤', DIM)
        self.y += 1

    def print_node_and_machine(self):
        self.stdscr.addstr(self.y, 0, '├─', DIM)
        self.stdscr.addstr(self.y, 2, ' node progress ', color(CYAN))
        self.stdscr.addstr(self.y, 17, '─'*19 + '┼─', DIM)
        self.stdscr.addstr(self.y, 38, ' machine stats ', color(CYAN))
        self.stdscr.addstr(self.y, 53, '─'*26 + '┤', DIM)
        self.y += 1

    def print_payload_info(self):
        self.stdscr.addstr(self.y, 0, '├─', DIM)
        self.stdscr.addstr(self.y, 2, ' payload info ', color(CYAN))
        self.stdscr.addstr(self.y, 16, '─'*20 + '┴─', DIM)
        self.stdscr.addstr(self.y, 37, '─'*42 + '┤', DIM)
        self.y += 1

    def print_bottom_line(self):
        self.stdscr.addstr(self.y, 0, '└' + '─'*78 + '┘', DIM)

    def print_info_line(self, pairs, sep=" │ ", end="│", prefix="", dynaidx=None):
        x = 0
        infos = []

        for info in pairs:
            infolen = len(info[1]) + len(info[2])
            if infolen == 0:
                infos.append(" ".ljust(info[0]+2))
            else:
                infos.append(" %s : %s %s" % (
                    info[1], info[2], " ".ljust(info[0]-infolen)))

        self.stdscr.addstr(self.y, x, '│', DIM)
        x += 1
        for info in infos:
            self.stdscr.addstr(self.y, x, prefix + info + " ")
            x += len(info)
            self.stdscr.addstr(self.y, x, sep, DIM)
            x += len(sep)
            self.stdscr.addstr(self.y, x, " ", DIM)
            x += len(" ")

        self.y += 1

    def refresh(self):
        self.y = 0
        self.stdscr.refresh()


class MonitorData:
    def __init__(self, workdir):
        self.workdir = workdir
        self.exec_avg = 0
        self.slave_stats = []
        self.load_initial()

    def load_initial(self):
        self.cpu = psutil.cpu_times_percent(interval=0.01, percpu=False)
        self.mem = psutil.virtual_memory()
        self.cores_phys = psutil.cpu_count(logical=False)
        self.cores_virt = psutil.cpu_count(logical=True)
        self.stats = self.read_file("stats")

        # add slave stats
        num_slaves = self.stats.get("num_slaves",0)
        for slave_id in range(0, num_slaves):
            self.slave_stats.append(self.read_file("slave_stats_%d" % slave_id))
            self.starttime = min([x["start_time"] for x in self.slave_stats])

        # add node information
        self.nodes = {}
        for metadata in glob.glob(self.workdir + "/metadata/node_*"):
            self.load_node(metadata)
        self.aggregate()

    def load_node(self, name):
        node_id = int(name.split("_")[-1])
        self.nodes[node_id] = self.read_file("metadata/node_%05d" % node_id)

    def runtime(self):
        return max([x["run_time"] for x in self.slave_stats])

    def aggregate(self):
        self.aggregated = {
            "fav_states": {},
            "normal_states": {},
            "exit_reasons": {"regular": 0, "crash": 0, "kasan": 0, "timeout": 0},
            "last_found": {"regular": 0, "crash": 0, "kasan": 0, "timeout": 0}
        }

        for nid in self.nodes:
            node = self.nodes[nid]
            self.aggregated["exit_reasons"][node["info"]["exit_reason"]] += 1
            if node["info"]["exit_reason"] == "regular":
                states = self.aggregated["normal_states"]
                if len(node["fav_bits"]) > 0:
                    states = self.aggregated["fav_states"]
                nodestate = node["state"]["name"]
                states[nodestate] = states.get(nodestate, 0) + 1

            last_found = self.aggregated["last_found"][node["info"]["exit_reason"]]
            this_found = node["info"]["time"]
            if last_found < this_found:
                self.aggregated["last_found"][node["info"]["exit_reason"]] = this_found

    def load_slave(self, id):
        self.slave_stats[id] = self.read_file("slave_stats_%d" % id)

    def load_global(self):
        self.stats = self.read_file("stats")

    def node_size(self, nid):
        return self.nodes[nid]["payload_len"]

    def node_parent_id(self, nid):
        return self.nodes[nid]["info"]["parent"]    

    def num_slaves(self):
        return len(self.slave_stats)

    def num_found(self, reason):
        return self.aggregated["exit_reasons"][reason]

    def cpu_used(self):
        return self.cpu.user + self.cpu.system

    def ram_used(self):
        return 100 * float(self.mem.used) / float(self.mem.total)

    def slave_input_id(self, i):
        return self.slave_stats[i]["node_id"]

    def slave_stage(self, i):
        method = self.slave_stats[i].get("method", None)
        stage  = self.slave_stats[i].get("stage", "waiting...")
        if method:
            return "%s" % method[0:14]
        else:
            return stage[0:14]

    def execs_p_sec_avg(self):
        return self.total_execs()/self.runtime()

    def total_execs(self):
        return sum([x["total_execs"] for x in self.slave_stats])

    def time_since(self, reason):
        time_stamp = self.aggregated["last_found"][reason]
        if not time_stamp:
            return None
        return self.starttime + self.runtime() - time_stamp

    def bitmap_size(self):
        return 64 * 1024

    def bitmap_used(self):
        return self.stats["bytes_in_bitmap"]

    def p_coll(self):
        return 100.0 * float(self.bitmap_used()) / float(self.bitmap_size())

    def update(self, pathname, filename):
        if "node_" in filename:
            self.load_node(pathname + "/" + filename)
            self.aggregate()
        elif "slave_stats" in filename:
            for i in range(0, self.num_slaves()):
                self.load_slave(i)
        elif filename == "stats":
            self.load_global()

    def read_file(self, name):
        retry = 4
        data = None
        while retry > 0:
            try:
                data = read_binary_file(self.workdir + "/" + name)
                break
            except:
                retry -= 1
        if data:
            return msgpack.unpackb(data, raw=False, strict_map_key=False)
        else:
            return None


class MonitorDrawer:
    def __init__(self, stdscr):
        global WORKDIR

        # mutex lock
        self.inf_mutex = Lock()
        self.key = Lock()

        # create pairs of forground and background colors
        curses.init_pair(WHITE, curses.COLOR_WHITE, curses.COLOR_BLACK)
        curses.init_pair(RED, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(GREEN, curses.COLOR_GREEN, curses.COLOR_BLACK)
        curses.init_pair(YELLOW, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(BLUE, curses.COLOR_BLUE, curses.COLOR_BLACK)
        curses.init_pair(MAGENTA, curses.COLOR_MAGENTA, curses.COLOR_BLACK)
        curses.init_pair(CYAN, curses.COLOR_CYAN, curses.COLOR_BLACK)

        # set default color pair
        stdscr.bkgd(curses.color_pair(1))

        # create drawing interface
        self.inf = MonitorInterface(stdscr)
        self.stdscr = stdscr

        # create initial statistics
        self.finished = False
        self.data = MonitorData(WORKDIR)

        # create child threads for loop
        self.watcher = Thread(target=self.watch, args=(WORKDIR,))
        self.cpu_watcher = Thread(target=self.watch_cpu, args=())
        self.thread_loop = Thread(target=self.loop)

        # start watcher threads
        self.watcher.daemon = True
        self.watcher.start()
        self.cpu_watcher.daemon = True
        self.cpu_watcher.start()

        # start loop thread
        stdscr.refresh()
        self.thread_loop.start()
        self.thread_loop.join()
    
    def loop(self):
        while True:
            try:
                self.draw()
            finally:
                time.sleep(0.01)

    def watch(self, workdir):
        d = self.data
        mask = (inotify.constants.IN_MOVED_TO)
        self.inotify = inotify.adapters.Inotify()
        i = self.inotify
        i.add_watch(workdir, mask)
        i.add_watch(workdir + "/metadata/", mask)

        for event in i.event_gen(yield_nones=False):
            if self.finished:
                return
            self.inf_mutex.acquire()
            try:
                (_, type_names, path, filename) = event
                d.update(path, filename)
                self.draw()
            finally:
                self.inf_mutex.release()

    def watch_cpu(self):
        while True:
            if self.finished:
                return
            cpu_info = psutil.cpu_times_percent(interval=2, percpu=False)
            mem_info = psutil.virtual_memory()
            swap_info = psutil.swap_memory()
            self.inf_mutex.acquire()
            try:
                self.data.mem = mem_info
                self.data.cpu = cpu_info
                self.data.swap = swap_info
                self.draw()
            finally:
                self.inf_mutex.release()

    def draw(self):
        # statistic data
        d = self.data

        # enter critical section
        self.key.acquire()
        
        # fuzzer graphics
        self.inf.print_title()
        self.inf.print_guest_and_overall()
        self.inf.print_info_line([
            (46, "     run time", ptime(d.runtime())),
            (17, "  crash", "%s" % (pnum((d.num_found("crash")))))])
        self.inf.print_info_line([
            (46, "last new path", ptime(d.time_since("regular"))),
            (17, " addsan", "%s" % (pnum((d.num_found("kasan")))))])
        self.inf.print_info_line([
            (46, "   last crash", ptime(d.time_since("crash"))),
            (17, "timeout", "%s" % (pnum((d.num_found("timeout")))))])
        self.inf.print_info_line([
            (46, " last timeout", ptime(d.time_since("timeout"))),
            (17, "regular", "%s" % (pnum((d.num_found("regular")))))])
        self.inf.print_execution_and_map()
        self.inf.print_info_line([
            (29, "  total execs", pnum(d.total_execs())),
            (34, "      edges", "%s" % (pnum((d.bitmap_used()))))])
        self.inf.print_info_line([
            (29, "   exec speed", str(pnum(d.execs_p_sec_avg())) + "/sec"),
            (34, "map density", "%s" % pfloat(d.p_coll()) + "%")])
        self.inf.print_node_and_machine()
        for i in range(0, d.num_slaves()):
            nid = d.slave_input_id(i)
            if nid not in [None, 0]:
                self.inf.print_info_line([
                    (29, "      node id", str(d.slave_input_id(i))),
                    (34, "   cpu used", pnum(d.cpu_used()) + "%")])
                self.inf.print_info_line([
                    (29, "   now trying", d.slave_stage(i)),
                    (34, "memory used", pnum(d.ram_used()) + "%")])
            else:
                self.inf.print_info_line([
                    (29, "      node id", "N/A"),
                    (34, "   cpu used", pnum(d.cpu_used()) + "%")])
                self.inf.print_info_line([
                    (29, "   now trying", d.slave_stage(i)),
                    (34, "memory used", pnum(d.ram_used()) + "%")])
        
        # fetch payload from shared queue
        global PAYLOAD
        if not PAYQ.empty():
            PAYLOAD = PAYQ.get()
        payload_len = len(PAYLOAD)

        nid = d.slave_input_id(0)
        self.inf.print_payload_info()
        try:
            self.inf.print_info_line([
                (72, "    parent id", str(node_parent_id(nid)))])
        except:
            self.inf.print_info_line([
                (72, "    parent id", str(0))])
        self.inf.print_info_line([
            (72, "         size", pbyte(payload_len) + " bytes")])
        self.inf.print_info_line([
            (72, "      payload", PAYLOAD[:20])])
        self.inf.print_bottom_line()

        # refresh screen buffer
        self.inf.refresh()

        # exit critical section
        self.key.release()

def run(stdscr):
    try:
        MonitorDrawer(stdscr)
    except:
        return


def main(workdir):
    global WORKDIR, SVCNAME
    
    WORKDIR = workdir
    SVCNAME = 'testDriver'  # todo - receive in args

    signal.signal(signal.SIGINT, sigint_handler)

    # delay for files to be generated
    time.sleep(2)

    curses.wrapper(run)