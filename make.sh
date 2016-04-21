#!/bin/bash
rm -f *.o
gcc -c -DHAVE_CONFIG_H -DLOCALEDIR=\"/usr/local\" *.c -I ./ 
gcc *.o -o daemond
