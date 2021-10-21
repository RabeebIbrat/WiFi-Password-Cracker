#ifndef WIFI_PASSWORD_CRACKER_STD_TINS_H
#define WIFI_PASSWORD_CRACKER_STD_TINS_H

#include<bits/stdc++.h>
#include<unistd.h>  //for "usleep"
#include<tins/tins.h>
using namespace std;
using namespace chrono;
using namespace Tins;

struct APStat {
    string SSID;
    HWAddress<6> MAC;
    int channel;

    APStat() {}

    APStat(string ssid, const HWAddress<6> &mac, int channel) : SSID(move(ssid)), MAC(mac), channel(channel) {}

    string to_string() const {
        string str;
        str += "SSID: [" + SSID + "]\n";
        str += "MAC: " + MAC.to_string() + "\n";
        str += "Channel: " + ::to_string(channel) + "\n\n";
        return str;
    }
};

#define eapolCapTimeout 100  //ms

struct EapolShake {
    RadioTap* radioEapol[4]{};
    int captures = 0;
    time_point<steady_clock> lastCap = steady_clock::now();

    bool insert(RadioTap* radioTap) {  //NOTE: reference stored, NOT copied
        int msgNo = messageNo(*radioTap->find_pdu<RSNEAPOL>());
        delete radioEapol[msgNo-1];
        radioEapol[msgNo-1] = radioTap;

        if(duration_cast<milliseconds>(steady_clock::now()-lastCap).count() > eapolCapTimeout) {  //timeout
            captures = 0;
        }

        if(msgNo == captures+1) {
            captures++;
            lastCap = steady_clock::now();
        }
        else if(msgNo != captures)
            captures = 0;

        return captureComplete();
    }

    bool captureComplete() const {
        return (captures == 4);
    }

    static int messageNo(const RSNEAPOL& rsn) {
        int msgNo = 1;
        if(!rsn.key_ack())
            msgNo += 1;
        if(rsn.secure())
            msgNo += 2;
        return msgNo;
    }


    ~EapolShake() {
        for(auto* i: radioEapol) {
            delete i;
        }
    }
};

#endif //WIFI_PASSWORD_CRACKER_STD_TINS_H
