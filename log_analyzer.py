import re
import Evtx.Evtx as evtx
from datetime import datetime as dt


def openLogFile(path):
    with open(path, 'r') as log_file:
        for log_entry in log_file:
            yield log_entry


def openEvtxFile(path):
    with evtx.Evtx(path) as log_file:
        for log_entry in log_file.records():
            yield log_entry.lxml()


def parseZeekConn(log_entry):
    log_data = re.split("\t", log_entry.rstrip())
    r = {}
    r["ts"] = dt.fromtimestamp(float(log_data[0]))
    r["uid"] = log_data[1]
    r["src_ip"] = log_data[2]
    r["src_port"] = log_data[3]
    r["dst_ip"] = log_data[4]
    r["dst_port"] = log_data[5]
    r["proto"] = log_data[6]
    r["service"] = log_data[7]
    r["duration"] = log_data[8]
    r["orig_bytes"] = log_data[9]
    r["resp_bytes"] = log_data[10]
    r["conn_state"] = log_data[11]
    r["local_orig"] = log_data[12]
    r["local_resp"] = log_data[13]
    r["missed_bytes"] = log_data[14]
    r["history"] = log_data[15]
    r["orig_pkts"] = log_data[16]
    r["orig_ip_bytes"] = log_data[17]
    r["resp_pkts"] = log_data[18]
    r["resp_ip_bytes"] = log_data[19]
    r["tunnel_parents"] = log_data[20]
    return r


def parseZeekdns(log_entry):
    log_data = re.split("\t", log_entry.rstrip())
    r = {}
    r["ts"] = dt.fromtimestamp(float(log_data[0]))
    r["uid"] = log_data[1]
    r["src_ip"] = log_data[2]
    r["src_port"] = log_data[3]
    r["dst_ip"] = log_data[4]
    r["dst_port"] = log_data[5]
    r["proto"] = log_data[6]
    r["trans_id"] = log_data[7]
    r["rtt"] = log_data[8]
    r["query"] = log_data[9]
    r["qclass"] = log_data[10]
    r["qtype"] = log_data[11]
    r["qtype_name"] = log_data[12]
    r["rcode"] = log_data[13]
    r["rcode_name"] = log_data[14]
    r["AA"] = log_data[15]
    r["TC"] = log_data[16]
    r["RD"] = log_data[17]
    r["RA"] = log_data[18]
    r["Z"] = log_data[19]
    r["answers"] = log_data[20]
    r["TTLs"] = log_data[21]
    r["rejected"] = log_data[22]
    return r


def parseZeekHttp(log_entry):
    log_data = re.split("\t", log_entry.rstrip())
    r = {}
    r["ts"] = dt.fromtimestamp(float(log_data[0]))
    r["uid"] = log_data[2]
    r["src_port"] = log_data[3]
    r["dst_ip"] = log_data[4]
    r["dst_port"] = log_data[5]
    r["trans_depth"] = log_data[6]
    r["method"] = log_data[7]
    r["host"] = log_data[8]
    r["uri"] = log_data[9]
    r["referrer"] = log_data[10]
    r["version"] = log_data[11]
    r["user_agent"] = log_data[12]
    r["origin"] = log_data[13]
    r["request_body_len"] = log_data[14]
    r["response_body_len"] = log_data[15]
    r["status_code"] = log_data[16]
    r["status_msg"] = log_data[17]
    r["info_code"] = log_data[18]
    r["info_msg"] = log_data[19]
    r["tags"] = log_data[20]
    r["username"] = log_data[21]
    r["password"] = log_data[22]
    r["proxied"] = log_data[23]
    r["orig_fuids"] = log_data[24]
    r["orig_filenames"] = log_data[25]
    r["orig_mime_types"] = log_data[26]
    r["resp_fuids"] = log_data[27]
    r["resp_filenames"] = log_data[28]
    r["resp_mime_types"] = log_data[29]
    return r


def parseSmb(log_entry):
    pattern = r"^(?P<ts>[0-9]{2}:[0-9]{2}:[0-9]{2})\s:\s(?P<client_hostname>[a-zA-Z0-9\-]+)\|(?P<client_ip>[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\|(?P<share>[a-zA-Z0-9\-]+)\|(?P<operation>[a-zA-Z]+)\|ok\|(?P<path>.*)$"

    log_data = re.search(pattern, log_entry)

    r = log_data.groupdict()
    r['ts'] = dt.strptime(r['ts'], "%H:%M:%S")
    if r['operation'] == 'rename':
        r['path'] = r['path'].split("|")[-1]
    return r


def parseEvtx(event):
    sys_tag = event.find("System", event.nsmap)
    event_id = sys_tag.find("EventID", event.nsmap)
    event_ts = sys_tag.find("TimeCreated", event.nsmap)
    event_data = event.find("EventData", event.nsmap)
    r = {}
    r["ts"] = event_ts.values()[0]
    r["eid"] = event_id.text
    for data in event_data.getchildren():
        r[data.attrib["Name"]] = data.text
    return r


def detectRundll32(path):
    log_file = openEvtxFile(path)
    for log_entry in log_file:
        try:
            log_data = parseEvtx(log_entry)
            if log_data["eid"] == "4688" and log_data["CommandLine"]:
                if "rundll32" in log_data["NewProcessName"] and re.search("powershell|cmd", log_data["ParentProcessName"]):
                    print(log_data["CommandLine"])
        except:
            pass
