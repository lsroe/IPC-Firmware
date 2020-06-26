#!/bin/bash

GHIDRA_PATH=<Path to the Ghidra directory, eg. ghidra_9.1.2_PUBLIC>

$GHIDRA_PATH/support/analyzeHeadless . tmp_ghidra -import $1 -postscript CallShowConstantUse.py

rm -r tmp_ghidra.rep
rm tmp_ghidra.gpr

