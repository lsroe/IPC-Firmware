 #!/bin/sh
# Preprocessing script for Ghidra raw output data

awk '$NF=="(GhidraScript)" {$NF=""; print $0 }' $1 | awk '$1== "INFO" {$1=$2=""; print $0}' | awk '{$1=$1;print}'
