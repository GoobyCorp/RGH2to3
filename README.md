# RGH2 to RGH3 by DrSchottky

### Usage:
```
usage: 2to3.py [-h] [-k CPUKEY] eccfile infile outfile

RGH2 to RGH3 by DrSchottky v1.0.0.0

positional arguments:
  eccfile               The ECC file to apply
  infile                The flash image to convert to RGH3
  outfile               The flash image to output to

options:
  -h, --help            show this help message and exit
  -k CPUKEY, --cpukey CPUKEY
                        The CPU key for the given flash image
```
With Glitch2m/MFG images use 00000000000000000000000000000000 as CPU Key  

### Known limitations:
- Bad Blocks before Xell (addr 0x70000, blocks 0x0-0x3 on BB, blocks 0x0-0x1B on SB) have to be manually remapped
- Misc

### Credits:
- 15432 for RGH3
- build.py creators for ECC code
- GoobyCorp for rewriting the code for Python 3.10