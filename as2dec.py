# Before running the script, run below command in separate terminal
# java -cp pad_oracle.jar:dec_oracle.jar:bcprov-jdk15-130.jar:python_interface_v1_2.jar python_interface_v1_2
# Run the script as
# python as2dec.py <m>
from oracle_python_v1_2 import pad_oracle, dec_oracle
import sys
import binascii
import time
import re
from binascii import hexlify,unhexlify
from itertools import cycle,izip

#this is for padding a block of the message
def pad_msg(hex_msg,block_size):
    msg_blocks = split_len(hex_msg,2)
    #print msg_blocks
    msg_len = len(msg_blocks)
    padstring = ''
    if(msg_len != 8):
        n = block_size - (msg_len % block_size)
        i = 0
        while( i < n):
            pad_block = '0' + str(n)
            padstring = padstring + pad_block
            i = i + 1
        return hex_msg+padstring
    else:
        return hex_msg

#xor operation of 2 hex numbers
def hex_xor(s1,s2):
    return hexlify(''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(unhexlify(s1), cycle(unhexlify(s2)))))

#split cipher according to block_size
def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]

#encrypt each block with CBC type using the dec_oracle function
def enc_msg_cbc(iv,hex_msg_blocks):
    enc_msg_blocks = []
    i = 0
    for i in range(0,len(hex_msg_blocks)):
        enc_msg = ''
        if(i == 0):
            enc_msg = dec_oracle("0x"+iv,"0x"+hex_msg_blocks[i])
            enc_msg_blocks.insert(i,enc_msg)
        else:
            enc_msg = dec_oracle(enc_msg_blocks[i-1],"0x"+hex_msg_blocks[i])
            enc_msg_blocks.insert(i,enc_msg)
    return enc_msg_blocks


iv = 'AC21AB15BC21EA11'
block_size = 16
result = []
msg = sys.argv[1]
hex_msg = msg.encode("hex")
hex_msg = hex_msg.upper()
#print hex_msg
#print hex_msg.decode("hex")
print "Chosen IV is: 0x"+iv.lower()
print "Input message is: "+msg
print "Doing CBC encryption"
#Split into blocks based on size
hex_msg_blocks = split_len(hex_msg,block_size)
#send the last block to see if padding needs to be done
hex_msg_blocks[-1] = pad_msg(hex_msg_blocks[-1],8)
result = enc_msg_cbc(iv,hex_msg_blocks)
print "Encrypted msg is: "
print '\t'.join([item for item in result])
