#!/bin/csh
# sample script
# csh file
# really long long long long long long line
# v1.0 01/2018 original creator

# check if we have all needed arguments
if ( $# == 0 ) then
    echo "usage: $0 bmf*bmf isis*isis surfaces#surface*00t variable:bmf options=1,2,3 logical@ output*csv"
    exit
endif

date +"$0 %x %X start"
echo $0 $*
sleep 3
echo "finished"
