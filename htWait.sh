#!/bin/bash

cd $1;

while true; do
    change=$(inotifywait -r -e close_write,moved_to,create . 2> /dev/null);
    change=${change#./ * };
    if [[ $change =~ (^|\ )\.htaccess$ ]]; then
        perl -I /root/x-manager/ /root/x-manager/htParser2.pl "$change" `pwd`
    fi;
done
