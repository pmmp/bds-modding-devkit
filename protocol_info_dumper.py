import subprocess
import re
import struct
import sys
import os
import threading
import json
import queue

if len(sys.argv) < 2:
    exit("Args: <BDS binary path> [output JSON file path]")

def convert_windows_path(path):
    return path.replace('\\', '/').replace('C:', '/mnt/c')

bds_path = convert_windows_path(sys.argv[1])
if len(sys.argv) == 3:
    output_file_path = convert_windows_path(sys.argv[2])
else:
    output_file_path = 'protocol_info.json'

print('Dumping data from ' + bds_path)
print('Output file path ' + output_file_path)

asm_regex = re.compile(r'.*\$(0x[A-Fa-f\d]+),%eax.*')
symbol_match_regex = re.compile(r'([\da-zA-Z]+) (.{7}) (\.[A-Za-z\d_\.]+)\s+([\da-zA-Z]+)\s+(?:Base|\.hidden)?\s+(.+)')
rodata_offset_regex = re.compile(r"^\s*\d+\s+\.rodata\s+[\da-f]+\s+[\da-f]+\s+([\da-f]+)\s+([\da-f]+)")

def get_value_at(file, offset, size, format):
    file = open(file, 'rb')
    if offset == None or offset < 0:
        return -1
    file.seek(offset)
    return struct.unpack(format, file.read(size))[0]

def stop_address(start, size):
    return hex(int('0x' + start, 16) + int('0x' + size, 16))

def dump_packet_id(start, size, symbol):
    proc = subprocess.Popen(['objdump', '--disassemble', '--demangle', '--section=.text', '--start-address=0x' + start, '--stop-address=' + stop_address(start, size), bds_path], stdout=subprocess.PIPE)
    lines = []
    while True:
        line_bytes = proc.stdout.readline()
        if not line_bytes:
            break
        line = line_bytes.decode('utf-8')
        lines.append(line)
        parts = line.split('mov')
        if len(parts) < 2:
            continue
        matches = re.match(asm_regex, parts[1])
        if not matches:
            continue
        return int(matches.groups()[0], 16)
    for l in lines:
        print(l)
    raise Exception("Packet ID not found for symbol " + symbol)

def dump_packet_id_threaded(start, size, symbol, packet_name, packets, packets_lock):
    id = dump_packet_id(start, size, symbol)
    packets_lock.acquire()
    packets[packet_name] = id
    print('Found ' + packet_name + ' ' + hex(id))
    packets_lock.release()

def parse_symbol(symbol):
    parts = re.match(symbol_match_regex, symbol)
    if not parts:
        raise Exception("Regex match failed for \"" + symbol + "\"")
    if len(parts.groups()) < 5:
        raise Exception("Wrong number of matches for \"" + symbol + "\" " + str(len(parts.groups())))
    start = parts.groups()[0]
    flags = parts.groups()[1]
    section = parts.groups()[2]
    size = parts.groups()[3]
    symbol = parts.groups()[4]
    return start, flags, section, size, symbol

def worker(symbol_queue, packets, packets_lock, stop_event, symbol_added_event):
    while not stop_event.is_set():
        try:
            s = symbol_queue.get_nowait()
        except queue.Empty:
            symbol_added_event.wait()
            continue

        start, size, symbol, packet_name = s

        dump_packet_id_threaded(start, size, symbol, packet_name, packets, packets_lock)
        symbol_queue.task_done()

def dump_packet_ids():
    packets = {}
    packets_lock = threading.Lock()
    symbol_queue = queue.Queue()
    symbol_added_event = threading.Event()
    stop_event = threading.Event()

    threads = [None] * 2

    for i in range(len(threads)):
        t = threading.Thread(target=worker, args=(symbol_queue, packets, packets_lock, stop_event, symbol_added_event))
        t.start()
        threads[i] = t

    proc = subprocess.Popen(['objdump --demangle -tT --dwarf=follow-links \'' + bds_path + '\' | grep Packet | grep \'::getId()\''], shell=True, stdout=subprocess.PIPE)
    while True:
        symbol = proc.stdout.readline()
        if not symbol:
            break
        start, _, _, size, symbol = parse_symbol(symbol.decode('utf-8'))
        packet_name = '::'.join(symbol.split('::')[:-1]) #apparently packets can be namespaced now ???
        match = re.search(r"SerializedPayloadPacket<(\w+?)Info,\s*(\w+?)Payload>", packet_name)
        if match and match.group(1) == match.group(2):
            packet_name = match.group(1)

        symbol_queue.put((start, size, symbol, packet_name))
        symbol_added_event.set()

    symbol_queue.join()
    stop_event.set()
    symbol_added_event.set() #interrupt sleepers
    for t in threads:
        t.join()
    return packets

def get_rodata_file_shift():
    proc = subprocess.Popen(['objdump -h -j \'.rodata\' \'' + bds_path + '\''], shell=True, stdout=subprocess.PIPE)
    while True:
        line = proc.stdout.readline()
        if not line:
            break
        matches = re.match(rodata_offset_regex, line.strip().decode('utf-8'))
        if matches:
            lma = int('0x' + matches.groups()[0], 16)
            physical_address = int('0x' + matches.groups()[1], 16)
            return physical_address - lma
    raise Exception("Unable to calculate offset for .rodata")

def dump_version():
    rodata_shift = get_rodata_file_shift()
    proc = subprocess.Popen(['objdump --demangle -tT --dwarf=follow-links \'' + bds_path + '\' | grep SharedConstants'], shell=True, stdout=subprocess.PIPE)
    major = None
    minor = None
    patch = None
    revision = None
    beta = False
    protocol = None
    while True:
        symbol = proc.stdout.readline()
        if not symbol:
            break
        start, _, _, size, symbol = parse_symbol(symbol.decode('utf-8'))
        if symbol.endswith('MajorVersion'):
            major = get_value_at(bds_path, int('0x' + start, 16) + rodata_shift, int('0x' + size, 16), 'i')
        elif symbol.endswith('MinorVersion'):
            minor = get_value_at(bds_path, int('0x' + start, 16) + rodata_shift, int('0x' + size, 16), 'i')
        elif symbol.endswith('PatchVersion'):
            patch = get_value_at(bds_path, int('0x' + start, 16) + rodata_shift, int('0x' + size, 16), 'i')
        elif symbol.endswith('RevisionVersion'):
            revision = get_value_at(bds_path, int('0x' + start, 16) + rodata_shift, int('0x' + size, 16), 'i')
        elif symbol.endswith('IsBeta'):
            beta = get_value_at(bds_path, int('0x' + start, 16) + rodata_shift, int('0x' + size, 16), 'B') == 1
        elif symbol.endswith('NetworkProtocolVersion'):
            protocol = get_value_at(bds_path, int('0x' + start, 16) + rodata_shift, int('0x' + size, 16), 'i')

    print('Version: %d.%d.%d.%d\nProtocol version: %d\nBeta: %d' % (major, minor, patch, revision, protocol, beta))
    return {
        "major": major,
        "minor": minor,
        "patch": patch,
        "revision": revision,
        "beta": beta,
        "protocol_version": protocol
    }

version = dump_version()
packets = dump_packet_ids()
output_data = {}
output_data["version"] = version
output_data["packets"] = dict(sorted(packets.items(), key=lambda item: item[1]))

with open(output_file_path, 'w') as output_file:
    json.dump(output_data, output_file, indent=4)

print('Done!')
