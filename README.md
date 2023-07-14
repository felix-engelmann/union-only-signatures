# Union Only Signatures

This repository holds the prototype implementation of the research paper 

> The State of the Union: Union-Only Signatures for Data Aggregation

available at https://ia.cr/2022/867

In `src/lib.rs` we implement a `UOSignature` which allows using different signature schemes.

An example use is presented in `src/bin/plots.rs`.
## Testing

Run all tests with 

    cargo test

## Benchmarking

We use criterion for benchmarks. Enable the wanted tests by commenting out the correct line at the end of `benches/timings.rs`.
Optionally you can tweak the parameter ranges in the file too.
Then run

    cargo bench

### Plot Generation

The plots in the paper for signing/verifying and merging are created by running the `make-plots.py` and `make-merging.py`.
The scripts take the benchmark output and generate pgfplot `\allplot` commands to be included in a figure.
