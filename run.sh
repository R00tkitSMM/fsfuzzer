#!/bin/bash

echo "[*] did you SCP the latest version?"

if ! sudo kextstat | grep -q "Pishi"; then
    echo "Loading Pishi..."
    sudo kmutil load -b Kcov.macOS.Pishi
else
    echo "Pishi already loaded"
fi

sleep 1

while true; do
    python gen.py

    ./fuzz_filesys ./corpus_binary \
        -timeout=5 
        [ $? -ne 0 ] && break
done
#./fuzz_filesys ./corpus_binary -timeout=5 -rss_limit_mb=4096 -max_total_time=100