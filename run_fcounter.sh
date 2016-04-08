#!/bin/bash

for bench in ../graphBig/qsim/*.tar; do
    echo $bench
    bench_name=$(basename $bench .tar);
    printf $bench_name "," >> counter.out
    sed "s#BENCH#$bench#g" run_orig.sh > $bench_name.sh
    chmod +x $bench_name.sh
    ./$bench_name.sh
    mv counter.out $bench_name.out
done
