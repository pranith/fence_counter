#!/bin/bash

for bench in ../graphbig/qsim/*.tar; do
    bench_name=$(basename $bench .tar);
    sed "s#BENCH#$bench#g" run_orig.sh > bench_${bench_name}.sh
    chmod +x bench_${bench_name}.sh
done

ls ./bench*.sh | parallel -j8
