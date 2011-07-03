#Fuzzface 
```
    version 0.1010:
```
Fuzzface is a protocol fuzzer. Given a directory of pcap files Fuzzface will alter
the data and write it to a socket (still in pcap format). Currently, Fuzzface is
a dumb fuzzer (random changes), but it is intended to turn into a dumb fuzzer.

## Features
    - Randomly fuzzes 10% of pcap file data (excluding pcap headers)
    - Recursively parses a directory for pcap files
    - Results are repeatable using provided seed
    - Only works for pcaps with ethernet link layer (not a cool feature...)

## Building
make

## Usage
./fuzzface <directory> <server ip address> <server port> [seed value]

## Dependencies
Boost 1.46.0+ (or simply 1.42.0+ with filesystem v3 enabled)

