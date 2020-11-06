"""This program decodes a .cap file encrypted with the RC4 algorithm"""

import numpy as np
from scapy.all import *


def convert_to_ascii(s):
    """Gives the unicode value for the elements in the list s"""
    return [ord(c) for c in s]


def KSA(key, IV):
    """This is the Key Scheduling Algorithm
       Expected arguments: the key of the network and the IV
       This function returns a permutation of the S vector"""
    key_iv = IV + key
    key_length = len(key_iv)
    S = [x for x in range(256)]
    j = 0

    for i in range(256):
        j = (j + S[i] + key_iv[i % key_length]) % 256
        S[i], S[j] = S[j], S[i]
    return S


def PRGA(S, n):
    """This is the Pseudo-Random Generation Algorithm
    Expected arguments: S = The permutation of the S vector created in the KSA function,
    n = The length of the data array
    This function returns a pseudo-random stream of bits"""

    i = 0
    j = 0
    keystream = []

    while n > 0:
        i = (i + 1) % 256
        j = (j + S[i]) % 256
        S[i], S[j] = S[j], S[i]
        K = S[(S[i] + S[j]) % 256]
        keystream.append(K)
        n -= 1

    return keystream


def convert_to_hex(lst):
    """Converts the elements of the given list to hexadecimal value"""
    hex_lst = []
    for i in lst:
        k = '{:x}'.format(i)
        hex_lst.append(int(k, 16))

    return hex_lst


def prep_data_iv(data):
    """Puts the data or IV in the right format"""
    result = []
    data2 = data.split()
    for i in data2:
        result.append(int(i, 16))

    return result


def lst_to_str(lst):
    """Makes a string of the given list"""
    str1 = ""
    for i in lst:
        str1 += i

    return str1


cap = input("Give the CAP file (and destination) you want to analyse: ")
packet_file = rdpcap(cap)

key = 'Groep'

raw_ivs = []
raw_data = []

ivs = []
data = []

# Iterate trough all the packets in the packet file 
# if the packet has the 802.11 protocol and it has data, make a list of the IV and the data
for pkt in packet_file:
    if pkt.haslayer(Dot11WEP) and pkt.type == 2 and len(pkt.payload) > 0:
        raw_ivs.append(pkt[1][1].iv)
        raw_data.append(pkt[1][1].wepdata)

        ivs.append(linehexdump(pkt[1][1].iv, onlyhex=1, dump=True))
        data.append(linehexdump(pkt[1][1].wepdata, onlyhex=1, dump=True))

for i in range(0, len(data)):
    d = data[i]
    iv = ivs[i]

    ascii_key = convert_to_ascii(key)
    hex_key = convert_to_hex(ascii_key)
    hex_iv = prep_data_iv(iv)

    prep_d = prep_data_iv(d)

    S = KSA(hex_key, hex_iv)
    keystream = PRGA(S, len(prep_d))

    np_keystream = np.array(keystream)
    np_testd = np.array(prep_d)

    decoded = np.bitwise_xor(np_keystream, np_testd)
    decoded2 = [chr(i) for i in decoded]
    decoded_text = lst_to_str(decoded2)
    print(decoded_text)
