#! /bin/bash
NB=$1
export LD_LIBRARY_PATH=/usr/local/lib
./bin/click mininet/switch/configs/forward_sw$NB.click