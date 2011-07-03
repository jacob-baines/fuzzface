#Fuzzface 
```
    version 0.1011:
```
Fuzzface is a protocol fuzzer. Given a directory of pcap files Fuzzface will alter
the data and write it to a socket (still in pcap format). Currently, Fuzzface is
a dumb fuzzer (random changes), but it is intended to turn into a dumb fuzzer.

## On Fuzzing and Why This Project?
When working with network protocols the developer sometimes makes assumptions like
'well this field will NEVER look like X', 'Checksums would catch any malformed
data', or (my favorite) 'I don't have any captures that do Z!' Because of these
assumptions (and others) developers often don't write code that is defensive enough
to handle protocol variants or simply messed up data in the wild. We hope a lot of these
kinks get worked out through unit tests, code reviews, or even QA. Unfortunately,
there will always be those evil packets that put our software into infinite
loops or cause it to crash. In my experience, these packets typically have some
'unexpected' quality. That's where a fuzzer can come in handy.

While there are some excellent fuzzers out there I couldn't find a fuzzer that
did quite what I wanted. Namely load a directory of files, fuzz them, and forward
the packets on to a follow on process with little to no configuration. Thus
this project was born.

## Features
    - Randomly fuzzes 10% of pcap file data (excluding pcap headers)
    - Recursively parses a directory for pcap files
    - Results are repeatable using provided seed
    - Only works for pcaps with ethernet link layer (not a cool feature...)

## Building
make

## Usage
```
./fuzzface <directory> <server ip address> <server port> [seed value]
```

## Dependencies
Boost 1.46.0+ (or simply 1.42.0+ with filesystem v3 enabled)

