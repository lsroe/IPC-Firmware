#!/bin/sh
# Filtering script based on the dynamic symbols found in the binaries
# on the supplied path. Will return the full path of candidate binaries

FUNS=(
    "open",
    "fopen",
    "mkfifo",
    "mq_open",
    "shm_open",
    "shmat",
    "sem_open",
    "ftok",
    "inet_aton",
    "inet_addr",
    "inet_network",
    "htons",
    "gethostbyname",
    "execl",
    "execlp",
    "execle",
    "execv",
    "execve",
    "execvp",
    "execvpe",
    "popen",
    "system"
     )

FILES="$1/*"

for filepath in $FILES
do
    filename=$filepath
    CLEAN=$(readelf -Ds $filepath | awk -v name=$filename {'print name " " $9'})
    FILTERED=""
    for FUN in $FUNS
    do
        FILTERED="$FILTERED $(echo "$CLEAN" | awk -v fun=$FUN {'$2==fun; print $1'})"
    done
    echo "$FILTERED" | awk '!seen[$1]++' | awk NF
done
