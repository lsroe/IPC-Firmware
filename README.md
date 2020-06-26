# Tools for identifying interprocess communication in firmware with Ghidra

The tools in this repository may be used to identify communication channels between supplied binaries.


## Identifying and collecting relevant binaries 
Relevant binaries are identified by the dynamic symbols they contain. Additional symbols to identify binaries by may be added to the `filterELF.sh` file.

To identify relevant binaries and copy them for batch analysis, do the following:
```bash
./filterELF/filterELF.sh <firmware-binary-directory> | xargs -I{} cp -u {} <collected_binary-directory>
```

## Ghidra analysis of binaries
First, add the path of the Ghidra directory in the `ghidra_scripts/run_headless.sh` file. To analyze the collected binaries do:

```bash
cd ghidra_scripts
./run_headless.sh <collected_binary-directory> > ../data/ghidra_data_raw.txt
cd ..
```

The directory `data` contains the output of the Ghidra analysis of the Netgear AC1450 Router firmware.

## Preprocess the Ghidra output
Ghidra will output a lot of unwanted information. To get rid of it do:

```bash
./preprocess/preprocess.sh data/ghidra_data_raw.txt > data/ghidra_data_clean.txt
```

## Read and analyze the data with pandas
Change to a Python instance from within the `analysis` directory. In Python do:

```python
from analysis import *

df = readGhidra("../data/ghidra_data_clean.txt")
```
If you want to analyze partial function calls do:

```
# Get dataframe with entry for each call and argument
part_call = getPartialCall(df, "open")

# Get summary of a dataframe of partial calls
part_summ = getSummaryPartial(part) 

# For further analysis you may want to sort the data
part_summ.sort_values("Rep")
```

The same process works form complete function calls, with each entry of the dataframe being the complete call, if recoverable:

```python
calls = getCompleteCall(df, "open")
summ = getSummary(calls, "open")
summ.sort_values("Rep_x") 
```
