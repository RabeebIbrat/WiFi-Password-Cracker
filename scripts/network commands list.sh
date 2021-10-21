#!/bin/bash

#view interface
iwconfig
iwconfig wlo1
iw wlo1 info

#get channels
iwlist wlo1 channel
iw wlo1 info | grep channel

#change channel
iwconfig wlo1 channel 4
