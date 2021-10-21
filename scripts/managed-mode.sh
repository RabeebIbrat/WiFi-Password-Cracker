#!/bin/bash

service NetworkManager start
ifconfig wlo1 down
iwconfig wlo1 mode managed
ifconfig wlo1 up
