#!/bin/sh

frameworksVal="cis-aks-t1.2.0 cis-eks-t1.2.0 cis-v1.23-t1.0.1"

for val in $frameworksVal; do
    echo "Started updating framework '$val' subscections ids"
    python3 scripts/generate_subsections_ids.py -fw $val -clean true
    status_code=$?
    if [ $status_code -eq 0 ] 
    then
        echo "Completed updating framework '$val' subscections ids"
    else
        exit 1
    fi
done