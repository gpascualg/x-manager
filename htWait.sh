#!/bin/bash

cd $1;

while true; do
    change=$(inotifywait -r -e close_write,moved_to,create .);
    change=${change#./ * };
    echo $change;
    if [[ $change =~ (^|\ )\.htaccess$ ]]; then
        perl /root/x-manager/htParser.pl "$change" `pwd`
    fi;
done
