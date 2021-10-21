#include "std-tins.h"
#include "control.h"
#include "sniff.h"
#include "inject.h"
#include "wpa2.h"

string wirelessIf = "wlo1";

int main() {
    setToMonitor(wirelessIf);

    int choice;
    string SSID;
    APStat AP;
    while(true) {
        cout << "1. View nearby Wi-Fi" << endl;
        cout << "2. Capture EAPOL" << endl;
        cout << "3. Crack password" << endl;
        cout << "4. Exit" << endl;

        cin >> choice;
        if(choice == 2 || choice == 3) {
            char tmp;
            scanf("%c", &tmp);  //read new line

            cout << "Enter SSID: ";
            getline(cin,SSID);
        }

        if(choice == 1)
            viewNearbyWiFi(wirelessIf, (MAX_CHANNEL+2)*500);
        else if(choice == 2) {
            AP = getAPStat(SSID, wirelessIf);
            EAPOLCaptureThread(AP, wirelessIf);
        }
        else if(choice == 3) {
            crackWPA2(SSID);
        }
        else
            break;
    }

    setToManaged(wirelessIf);
}