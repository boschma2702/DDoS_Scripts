import json
import os

pretty_print = True


def write_rule(rule_name, data):
    rule = ["signature {} {{".format(rule_name)]
    protocol = data["protocol"]

    add_src_ip = True
    add_dst_ports = True
    add_src_ports = True

    if pretty_print: rule.append("\n")


    if protocol == "ICMP":
        add_to_str(rule, write_icmp_type(int(float(data["additional"]["icmp_type"].split(",")[0]))))
        add_dst_ports = False
        add_src_ports = False
        pass
    elif protocol == "NTP":
        pass
    elif protocol == "UDP":
        pass
    elif protocol == "TCP":
        add_to_str(rule, write_tcp_flags(data["additional"]["tcp_flag"]))
        pass
    elif protocol == "DNS":
        add_to_str(rule, write_dns_query(data["additional"]["dns_query"]))
        pass
    elif protocol == "IPv4":
        pass
    elif protocol == "Chargen":
        pass


    if add_src_ip:
        add_to_str(rule, write_src_ips(data["src_ips"]))

    if add_src_ports:
        add_to_str(rule, write_src_ports(data["src_ports"]))

    if add_dst_ports:
        add_to_str(rule, write_dst_ports(data["dst_ports"]))



    rule.append("\tevent \"{}\"".format(rule_name))
    if pretty_print: rule.append("\n")

    rule.append("}")

    return "".join(rule)


def write_protocol(protocol: str):
    return "ip-proto == {}".format(protocol)


def write_src_ips(ips: list):
    if len(ips) > 0:
        return "src-ip == {}".format(", ".join(ips))
    return ""


def write_dst_ips(ips: list):
    if len(ips) > 0:
        return "dst-ip == {}".format(", ".join(ips))
    return ""


def write_src_ports(ports: list):
    if len(ports) > 0:
        s = str(int(ports[0]))
        for i in range(1, len(ports)-1):
            s += ", "+str(int(ports[i]))
        return "src-port == {}".format(s)
    return ""


def write_dst_ports(ports: list):
    if len(ports) > 0:
        s = str(int(ports[0]))
        for i in range(1, len(ports)-1):
            s += ", "+str(int(ports[i]))
        return "dst-port == {}".format(s)
    return ""


def write_dns_query(query: str):
    return "payload /.*{}/".format(query)


def write_icmp_type(t: int):
    return "header icmp[0:1] == {}".format(str(t))


def write_tcp_flags(t: str):
    """
    This only works when the last bit of the reserved field of tcp and the ECN-nonce flag are set to 0
    """
    flags = t[4:]
    bin_flags = ""
    for c in flags:
        if c == "·":
            bin_flags += "0"
        else:
            bin_flags += "1"
    # print(bin_flags)
    return "header tcp[13:1] == {}".format(str(int(bin_flags, 2)))


def add_to_str(rule: list, to_add:str):
    if not to_add == "":
        if pretty_print:
            rule.append("\t"+to_add+"\n")
        else:
            rule.append(to_add)


def generate_signature(filename, file):
    json_file = json.load(file)
    rule_name = "STOP"+filename[:4]
    with open("sig.sig", "w") as sig_file:
        rule = write_rule(rule_name, json_file)
        sig_file.write(rule)

