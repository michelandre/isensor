import sys
import os
import struct
import logging
from ctypes import (CDLL, get_errno)
from ctypes.util import find_library
from socket import (
    socket,
    AF_BLUETOOTH,
    SOCK_RAW,
    BTPROTO_HCI,
    SOL_HCI,
    HCI_FILTER,
)

# https://git.kernel.org/pub/scm/bluetooth/bluez.git/tree/lib/hci.h
HCI_EVENT_PKT = 0x04
EVT_LE_META_EVENT = 0x3e

# https://www.bluetooth.com/specifications/assigned-numbers/generic-access-profile/
AD_ELEMENT_SHORTNAME = 0x08
AD_ELEMENT_MANUFACTURER = 0xFF

# Sensor flags
ISENSOR_ED_TAMPER_FLAG = 0b00000001
ISENSOR_ED_ALARM_FLAG = 0b00000010
ISENSOR_ED_LOWVOLTAGE_FLAG = 0b00000100
ISENSOR_ED_HEARTBEAT_FLAG = 0b00001000

if not os.geteuid() == 0:
    sys.exit("script only works as root")

btlib = find_library("bluetooth")
if not btlib:
    raise Exception(
        "Can't find required bluetooth libraries"
        " (need to install bluez)"
    )
bluez = CDLL(btlib, use_errno=True)

logging.basicConfig(
    format='%(asctime)s.%(msecs)03d %(levelname)-8s %(message)s',
    level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')

dev_id = bluez.hci_get_route(None)

sock = socket(AF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI)
sock.bind((dev_id,))



err = bluez.hci_le_set_scan_parameters(sock.fileno(), 0, 0x10, 0x10, 0, 0, 1000)
if err < 0:
    raise Exception("Set scan parameters failed")
    # occurs when scanning is still enabled from previous call

# allows LE advertising events
hci_filter = struct.pack(
    "<IQH", 
    0x00000010, 
    0x4000000000000000, 
    0
)
sock.setsockopt(SOL_HCI, HCI_FILTER, hci_filter)

err = bluez.hci_le_set_scan_enable(
    sock.fileno(),
    1,  # 1 - turn on;  0 - turn off
    0, # 0-filtering disabled, 1-filter out duplicates
    1000  # timeout
)
if err < 0:
    errnum = get_errno()
    raise Exception("{} {}".format(
        errnum,
        os.strerror(errnum)
    ))

try:
    last_frameid = {}
    while True:
        data = sock.recv(1024)

        #Sanity check, verify, should be handled by filter
        if data[0] != HCI_EVENT_PKT:
            raise Exception(f"Unexpected packet type received {data[0]} expected HCI_EVENT_PKT={HCI_EVENT_PKT}")
        if data[1] != EVT_LE_META_EVENT:
            raise Exception(f"Unexpected event type received {data[1]} expected HCI_EVENT_PKT={EVT_LE_META_EVENT}")
        
        addr = ':'.join("{0:02x}".format(x) for x in data[12:6:-1])
        addr = addr.lower()
 
        pkt = data
        # parse header (hci_event_hdr + evt_le_meta_event + record count)
        packet_type, evt, plen, subevent, numreports = struct.unpack("BBBBB", pkt[:5])
        pkt = pkt[5:] # remove header
        logging.debug(f"DEV {addr} t:{packet_type} evt:{evt} plen:{plen} subev:{subevent} numr:{numreports} data:{data}")
        data_offset = 0
        
        # parse le_advertising_info
        adv_info = struct.unpack("BB6BB", pkt[data_offset:data_offset+9])
        (evt_type, bdaddr_type, bdaddr, dlength) = (adv_info[0], adv_info[1], adv_info[2:8], adv_info[8])
        bdaddr_s = ':'.join("{0:02x}".format(x) for x in reversed(bdaddr))
        data_offset += 9 # skip le_advertising_info
        logging.debug(f"ADV evt_type:{evt_type} bdaddr_type:{bdaddr_type} bdaddr:{bdaddr_s} dlength:{dlength} data:{pkt[data_offset:data_offset+dlength]}")
        
        #adv_data = pkt[data_offset:data_offset+dlength]
        end_offset = data_offset + dlength
        shortname = "<unknown>"
        mdata = None
        while(data_offset < end_offset):
            field_len, field_type = struct.unpack("BB",pkt[data_offset:data_offset+2])
            data_offset += 2 # Skip header
            field_data = pkt[data_offset:data_offset+field_len]
            if (field_type == AD_ELEMENT_SHORTNAME):
                try:
                    shortname = field_data.decode('utf-8').strip()                
                except UnicodeDecodeError:
                    shortname = f"{field_data}"
                    logging.info(f"[{bdaddr_s}] failed to decode shortname:{shortname}")

            elif (field_type == AD_ELEMENT_MANUFACTURER):
                mdata = field_data
            
            logging.debug(f"D l:{field_len} t:{field_type} off:{data_offset}->{data_offset + (field_len + 1)}:{end_offset}")
            data_offset += (field_len - 1)

        if (shortname == "iSensor"):
            (fw,d1,d2,d3,tid,ed,cd,checksum) = struct.unpack("BBBBBBBB",mdata[:8])
            if (last_frameid.get(bdaddr_s, 0xFFFF) != cd):

                sensor_open = (ed & ISENSOR_ED_ALARM_FLAG == ISENSOR_ED_ALARM_FLAG)
                sensor_hbt = (ed & ISENSOR_ED_HEARTBEAT_FLAG == ISENSOR_ED_HEARTBEAT_FLAG)
                sensor_tampered = (ed & ISENSOR_ED_TAMPER_FLAG == ISENSOR_ED_TAMPER_FLAG)
                sensor_lowbattery = (ed & ISENSOR_ED_LOWVOLTAGE_FLAG == ISENSOR_ED_LOWVOLTAGE_FLAG)

                logging.debug( f"{shortname}[{bdaddr_s}] fw:{fw} tid:{tid:08b} ed:{ed:08b} cd:{cd:08b} cs{checksum}")
                logging.info( f"{shortname}[{bdaddr_s}] {'HBT' if sensor_hbt else 'EVT'} {'OPEN' if sensor_open else 'CLOSED'} {'LOW' if sensor_lowbattery else ''} {'!!' if sensor_tampered else ''}")
                
            last_frameid[bdaddr_s] = cd
        
finally:
    bluez.hci_le_set_scan_enable(
        sock.fileno(),
        0,# 1 - turn on;  0 - turn off
        0,# 0-filtering disabled, 1-filter out duplicates
        1000  # timeout
        )
