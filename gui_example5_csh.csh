#!/bin/csh
# sample script

# check if we have all needed arguments
if ( $# == 0 ) then
    echo "usage: $0 bmf*bmf isis*isis surfaces#surface*00t variable:bmf options=1,2,3 logical@ output*csv"
    exit
endif

date +"$0 %x %X start"
echo $0 $*
sleep 1
echo "finished"
