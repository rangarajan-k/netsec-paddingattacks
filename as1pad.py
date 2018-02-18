# Before running the script, run below command in separate terminal
# java -cp pad_oracle.jar:dec_oracle.jar:bcprov-jdk15-130.jar:python_interface_v1_2.jar python_interface_v1_2
# Run the script as
# python as1pad.py <c0> <c1>
from oracle_python_v1_2 import pad_oracle, dec_oracle
import sys
import binascii
import time
import re
from binascii import hexlify,unhexlify
from itertools import cycle,izip

''' create custom block for the byte we search'''
def block_search_byte(block_size, i, pos, l):
    hex_char = hex(pos).split('0x')[1]
    return "00"*(block_size-(i+1)) + ("0" if len(hex_char)%2 != 0 else '') + hex_char + ''.join(l)

''' create custom block for the padding'''
def block_padding(block_size, i):
    l = []
    for t in range(0,i+1):
        l.append(("0" if len(hex(i+1).split('0x')[1])%2 != 0 else '') + (hex(i+1).split('0x')[1]))
    return "00"*(block_size-(i+1)) + ''.join(l)

# split the cipher in len of block_size
def split_len(seq, length):
    return [seq[i:i+length] for i in range(0, len(seq), length)]

def hex_xor(s1,s2):
    return hexlify(''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(unhexlify(s1), cycle(unhexlify(s2)))))

def test_padding(c0,c1):
    c0 = "0x"+c0
    c1 = "0x"+c1
    ret_pad = pad_oracle(c0, c1)
    return ret_pad

def padding_attack(iv,cipher,block_size):
    cipher = cipher.upper()
    text_size = block_size*2
    success = False
    valid_value = []
    result = []
    iv = iv.upper()
    cipher_block = split_len(cipher, text_size)
    print cipher_block
    #cipher_block = split_len(cipher,text_size)

    #for each block of cypher , here we have 1 block which is 64 bits
    for block in reversed(range(0,len(cipher_block))):
        print "[+] Search value block : ", block, "\n"
        for i in range(0,block_size):
            #check for random chars from 0 to 255
            for j in range(0,256):
                if j != i+1 or (len(valid_value) > 0 and int(valid_value[-1],16) == j):
                    bk = block_search_byte(block_size,i,j,valid_value)
                    bp = iv
                    bc = block_padding(block_size,i)

                    tmp = hex_xor(bk,bp)
                    cb = hex_xor(tmp,bc).upper()
                    up_cipher = cipher_block[block]

                    pad_result = test_padding(cb,up_cipher)

                    #Printing proceedings
                    exe = re.findall('..',cb)
                    discover = ('').join(exe[block_size-i:block_size])
                    current =  ('').join(exe[block_size-i-1:block_size-i])
                    find_me =  ('').join(exe[:-i-1])

                    sys.stdout.write("\r[+] Test [Byte %03i/256 - Block %d ]: \033[31m%s\033[33m%s\033[36m%s\033[0m" % (j, block, find_me, current, discover))
                    sys.stdout.flush()

                    if pad_result == '1':
                        success = True

                        value = re.findall('..',bk)
                        valid_value.insert(0,value[block_size-(i+1)])

                        print ''
                        print "[+] Block M_Byte : %s"% bk
                        print "[+] Block C_{i-1}: %s"% bp
                        print "[+] Block Padding: %s"% bc
                        print ''

                        bytes_found = ''.join(valid_value)
                        #if( i == 0 and bytes_found.decode("hex") > hex(block_size) and block == len())
                        print '\033[36m' + '\033[1m' + "[+]" + '\033[0m' + " Found", i+1,  "bytes :", bytes_found
                        print ''

                        break

            if success == False:
                #assuming padding is 01 for last block since probability is high
                #print "Cipher block length is " + len(cipher_block)
                if len(cipher_block)-1 == block and i == 0:
                    value = re.findall('..',bk)
                    valid_value.insert(0,"01")
                    print ''
                    print '[-] No padding found, but maybe the padding is length 01 :)'
                    print "[+] Block M_Byte : %s"% bk
                    print "[+] Block C_{i-1}: %s"% bp
                    print "[+] Block Padding: %s"% bc
                    print ''
                    bytes_found = ''.join(valid_value)
                else:
                    print "\n[-] Error decryption failed"
                    result.insert(0,''.join(valid_value))
                    hex_r = ''.join(result)
                    if len(hex_r) > 0 :
                        print "[+] Partial Decrypted value (HEX):", hex_r.upper()
                        padding = int(hex_r[len(hex_r)-2:len(hex_r)],16)
                        print "[+] Partial Decrypted value (ASCII):", hex_r[0:-(padding*2)].decode("hex")
                    sys.exit()
            success = False

        result.insert(0, ''.join(valid_value))
        valid_value = []

    print ''
    hex_r = ''.join(result)
    print "[+] Decrypted value (HEX):", hex_r.upper()
    padding = int(hex_r[len(hex_r)-2:len(hex_r)],16)
    print "[+] Decrypted value (ASCII):", hex_r[0:-(padding*2)].decode("hex")

    return hex_r[0:-(padding*2)].decode("hex")


# c0 is the IV, c1 is the Cipher text
c0 = sys.argv[1].lstrip("0x")
c1 = sys.argv[2].lstrip("0x")
print 'Command line arguments are'

print c0,c1

result = padding_attack(c0,c1,8)
