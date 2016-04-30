#!/bin/bash

for bench in *.out; do
    name=(`basename $bench .out`);
    cat $bench >> all.csv
done
