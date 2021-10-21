#!/bin/bash

service NetworkManager stop
ifconfig wlo1 down
iwconfig wlo1 mode monitor
ifconfig wlo1 up
