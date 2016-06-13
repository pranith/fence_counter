#!/bin/bash

for bench in *.out; do
    name=(`basename $bench .out`);
    echo -n $name >> all.csv
    cat $bench >> all.csv
done
