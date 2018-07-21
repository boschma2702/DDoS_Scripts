import json
import os
import signal
import time

import generator
from definitions import execute, network_device_ids, event_handler_path
from send_to_attacker import send_data

runs = 10


def send_message(s: str):
    send_data(s.encode())


def time_send():
    times = []
    for i in range(0, runs):
        start = time.clock()
        # send_message("BENCH")
        send_message("BENCH")
        end = time.clock()
        times.append(str(end-start))
    return times


def generate_signature(filename, file):
    json_file = json.load(file)
    rule_name = "STOP"+filename[:4]
    with open("sig.sig", "w") as sig_file:
        rule = generator.write_rule(rule_name, json_file)
        sig_file.write(rule)


def time_generate_file(filename, file_path):
    times = []
    for i in range(0, runs):
        start = time.clock()
        generate_signature(filename, open(file_path))
        stop = time.clock()
        times.append(str(stop-start))
    return times


def start_bro():
    return execute("sudo /usr/local/bro/bin/bro -b -i {} {}/sigEventHandler.bro".format(network_device_ids, event_handler_path)).pid


def stop_bro(pid):
    os.killpg(os.getpgid(pid), signal.SIGTERM)


def generate_all_sigs():
    directory = os.fsencode("json_files/")

    sig = ""
    for f in os.listdir(directory):
        filename = os.fsdecode(f)
        # json_files.append((filename, "json_files/" + filename))
        rule_name = "STOP" + filename[:4]
        sig += generator.write_rule(rule_name, json.load(open("json_files/" + filename))) + "\n"

    with open("sig.sig", "w") as sig_file:
        sig_file.write(sig)




if __name__ == '__main__':
    time_sending = "send to attacker times: \n{}\n".format("\n".join(time_send()))

    directory = os.fsencode("json_files/")

    json_files = []
    for f in os.listdir(directory):
        filename = os.fsdecode(f)
        json_files.append((filename, "json_files/"+filename))

    generating_times = ""
    for fn, p in json_files:
        generating_times += "Time for: {}\n".format(fn)
        generating_times += "\n".join(time_generate_file(fn, p))+"\n"

    with open("results-ids.txt", "w") as f:
        f.write(time_sending + generating_times)

    print("Starting attacks")
    # handle attacks
    for fn, p in json_files:
        # generate sig
        generate_signature(fn, open(p))
        for i in range(0, runs):
            # start bro
            pid = start_bro()
            # Send start command of attack
            send_message("START"+fn[:4])
            time.sleep(7)
            # Kill bro
            stop_bro(pid)
            # time.sleep(1)

    #Entering next phase, receiving with all sigs present
    print("STARTING NEXT PHASE")

    send_message("NEXT")
    generate_all_sigs()
    # handle attacks
    for fn, p in json_files:
        for i in range(0, runs):
            # start bro
            pid = start_bro()
            # Send start command of attack
            send_message("START" + fn[:4])
            time.sleep(7)
            # Kill bro
            stop_bro(pid)


    send_message("QUIT")
