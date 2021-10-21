#ifndef WIFI_PASSWORD_CRACKER_CONTROL_H
#define WIFI_PASSWORD_CRACKER_CONTROL_H

#include "std-tins.h"

#define MAX_CHANNEL 13

string exec(const char* cmd) {
    char buffer[128];
    string result;
    FILE* pipe = popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {
        while (fgets(buffer, sizeof buffer, pipe) != nullptr) {
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    return result;
}

void setToMonitor(const string& wirelessIf) {
    system("service NetworkManager stop");
    system("ifconfig wlo1 down");
    system("iwconfig wlo1 mode monitor");
    system("ifconfig wlo1 up");
}

void setToManaged(const string& wirelessIf) {
    system("service NetworkManager start");
    system("ifconfig wlo1 down");
    system("iwconfig wlo1 mode managed");
    system("ifconfig wlo1 up");
}

int getCurrentChannel(const string& wirelessIf) {
    string command = "iw dev " + wirelessIf + " info| grep channel | cut -d' ' -f2";
    return stoi(exec(command.c_str()));
}

void setChannel(const string& wirelessIf, int channel) {
    string command = "iwconfig " + wirelessIf + " channel " + to_string(channel);
    system(command.c_str());
}

void cycleChannels(const string& wirelessIf, int cyclePulse, const bool* endSwitch) {
    int currentChannel = getCurrentChannel(wirelessIf);
    usleep(cyclePulse*1000);
    while(!*endSwitch) {
        currentChannel++;
        if(currentChannel > MAX_CHANNEL) currentChannel = 1;
        setChannel(wirelessIf, currentChannel);
        usleep(cyclePulse*1000);
    }
}

#endif //WIFI_PASSWORD_CRACKER_CONTROL_H
