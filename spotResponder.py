from __future__ import print_function
import socket
from threading import Thread
import time
import json
import sys

from struct import pack, unpack
from base64 import b64decode, b64encode
from odict import OrderedDict

#CONFIG
eachsecond = 10

def banner():
    print ("""
                 ,=.
      +_.       /  /
      ; \____,-==-.-_*- - -SPOT
      //_    `----'-=)           @tfairane
      `  `'--/  /---/*- -RESPONDER
            /  /
            `='     spotResponder.py <broadcast>
            
SpotResponder is an active scanner to detect Responder running on ur LAN
            """)


class NBNSQuery():
    fields = OrderedDict([
    ("Tid",           "\xB4\x55"),
    ("Flags",         "\x01\x10"),
    ("Question",      "\x00\x01"),
    ("AnswerRRS",     "\x00\x00"),
    ("AuthorityRRS",  "\x00\x00"),
    ("AdditionalRRS", "\x00\x00"),
    #https://support.microsoft.com/en-us/kb/194203
    ("NbtName",       "\x20\x45\x48\x45\x46\x45\x45\x45"\
                        "\x42\x45\x47\x46\x46\x45\x4C\x45"\
                        "\x50\x46\x46\x46\x45\x45\x42\x45"\
                        "\x49\x45\x46\x46\x43\x45\x46\x43\x41\x00"),
    ("Type",          "\x00\x20"),
    ("Classy",        "\x00\x01")
    ])

    def __str__(self):
        return "".join(map(str, self.fields.values()))


def CounterResponder(broadcast, timeout=5):
    p = NBNSQuery()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(str(p), (broadcast, 137))
        s.settimeout(timeout)
        recv_data, addr = s.recvfrom(1024)
        if recv_data[7] == "\x01": #NBNSAnswer ?
            print ("RESPONDER:DETECTED IP:" + addr[0] + " PROTO:NBNS")
    except:
        print (".", end="")
    finally:
        s.close()


if __name__ == '__main__':
    banner()
    try:

        while True:
            if(len(sys.argv)!=2):
                exit(0)
            Thread(target=CounterResponder, args=(sys.argv[1],)).start()
            time.sleep(eachsecond)
    except KeyboardInterrupt:
        exit("bye ...")
