import subprocess, os

attacking_speed = 90

#TODO fill in values
attacker_ip = " "
target_mac = " "
target_ip = " "
network_device_attacker = " "
network_device_ids = " "

event_handler_path = " "


def execute(to_execute):
    return subprocess.Popen(to_execute, stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid)


def send_message(msg: str):
    execute("python3 send_to_attacker.py '{}'".format(msg)).wait()
