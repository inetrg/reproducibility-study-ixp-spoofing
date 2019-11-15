

# A Reproducibility Study of "IP Spoofing Detection in Inter-Domain Traffic"

This repository exposes the main program that we used in the paper *A Reproducibility Study of "IP Spoofing Detection in Inter-Domain Traffic"* [arXiv](https://arxiv.org/abs/1911.05164). Our implementation is inspired by the full cone implementation from [`transitive_closure_cone`](https://gitlab.inet.tu-berlin.de/thorben/transitive_closure_cone).

This program consist of a server and a client component. The `server` manages a customer cone that can be filled and queried via the client. To build a cone, the `client` importes AS relationship data and forwards it to the server. Queries sort a source IP combined with its originating AS number (in our study a IXP member) into one of the following categories:

* Bogon - Private or multicast source IP
* Unrouted - Unannounced source IP
* Invalid - Classified as spoofed
* Regular - Traffic without anomalies
* Unknown - No MAC to AS mapping present

For easier use, the `client` parses SFlow files and sends the source IP and the detected AS number of each containing flow to the `server`. For deeper inspection it analyzes the payload of each packet with PCAP. The classification results a written as gzip'd csv files into the given output folder.

## Prerequisites

This project require Cmake (>3.1) and a C++14 compiler to build. Most of the dependencies will be downloaded by cmake automatically. Only the following dev-libs must be installed:

* Ubuntu
  * libbz2-dev
  * libzip-dev
  * libpcap0.8-dev

To install them, run `sudo apt install libbz2-dev libzip-dev libpcap0.8-dev`.

* CentOS/Rhel
  * bzip2-devel
  * zlib-devel
  * libpcap
  * patch

To install them, run on CentOS run `sudo yum install bzip2-devel zlib-devel patch libpcap-devel`.

## Building

```bash
git clone https://github.com/inetrg/reproducibility-study-ixp-spoofing
cd reproducibility-study-ixp-spoofing
mkdir build
cd build
cmake ..
make -j4
```

The build outputs the programs `cc` and `cc-test`. `cc` is the main program and `cc-test` runs our unit-tests (`make test`).

## CLI Usage

`cc` has three modes (`client`, `client_stdin` and `server`) which each accept a range of additional options:

###### General options:

| Short | Long       | Description                                 |
| ----- | ---------- | ------------------------------------------- |
| -m    | --mode     | One of `server`, `client` or `client_stdin` |
| -P    | --port     | Port (default 1234)                         |
| -H    | --hostname | Host name (default 127.0.0.1)               |



###### Server mode options:

|Short|Long                  | Description                                             |
|-----|----------------------|---------------------------------------------------------|
|-T   |--allow_transitive_p2p| Allow transitive peer-to-peer relations (default false) |



###### Client mode options:

| Short | Long              | Description                                                  |
| ----- | ----------------- | ------------------------------------------------------------ |
| -i    | --input_path      | Path to sflow files in pcap format                           |
| -o    | --output_path     | Output path                                                  |
| -p    | --prefixes        | Prefixes as gzip file with following syntax (ASN: Prefix1,Prefix2,..) `1: 1.2.3.0\24, 2.2.0.0/16\n` |
| -b    | --bgp_relations   | Reads AS relations as gzip file with following syntax (ProviderASN CustumerASN) `1 2\n` |
| -c    | --caida_relations | Reads AS relationships as bzip file from [CAIDA AS relationship data](https://www.caida.org/data/as-relationships/) (serial-2) |
| -M    | --ass_mac_mapping | AS to MAC mapping as file with following syntax `asn; mac1,mac2\n` |
| -s    | --pattern         | Search pattern for input files (`"2019-04-01-.*\.pcap"`)     |
|       | --skip_asn        | ASN that is ignored in combination with the `--bgp_relations` or `--caida_relations` option. |
| -w    | --num_worker      | Number of worker (default 4)                                 |

###### STDIN Client mode options:

| Short | Long              | Description                               |
| ----- | ----------------- | ------------------------------------------|
| -F    | --read_prefixes   | Except lines like 9.9.9.9,10\n            |
| -R    | --read_relations  | Except lines like  c2p,1,2\n or p2p,1,2\n |
| -C    | --check           | Except lines like  8.8.8.8,2\n            |

## Results

The `client` outputs matching files to all SFlow files that match the search pattern with the same name and an `gz` extension in the output folder. Further, a single `stats.json.gz` file provides information about the classification results.

###### CSV schema

```bash
ASN,
CLASSIFICATION CLASS,      # One of (regular|bogon|unrouted|invalid)
SRC-IP,
DEST-IP,
SRC-MAC,
DEST-MAC,
PROTOCOL NUMBER,           # Picked from IP Layer
SRC-PORT,
DST-PORT,
TRAMSPORT PROTOCOL NAME,   # Determined with Pcap
APPLICATION PROTOCOL NAME, # Determined with Pcap
PACKET SIZE,
SAMPLE RATE,
TTL,
VLAN IN,
VLAN OUT,
TIMESTAMP,
CHECKS                      # Checks syntax {string;string;..:dest_port}
```

###### Checks

The checks are implemented in `src/client/checker.cpp`. At the moment the following checks are performed.

| Key                   | Description                                  |
| --------------------- | -------------------------------------------- |
| same-src-dst          | SRC and DST IP are the same                  |
| tcp-port-0            | TCP DST or SRC port is 0                     |
| udp-port-0            | UDP DST or SRC port is 0                     |
| request-payload-size  | HTTP request payload size                    |
| response-payload-size | HTTP response payload size                   |
| dns-request           | Is set if the packet is a DNS request        |
| dyn-ports             | DST port is in range between 49152 and 65535 |
| ack,syn,ack-psh,...   | Seeded TCP flags                             |




## Examples

###### Start server

```bash
./build/cc -m server
server is running in caf mode on port 1234
```

###### Add  [CAIDA AS relationship data](https://www.caida.org/data/as-relationships/) (serial-2)

```bash
./build/cc -m client -c [Path to the downloaded data]/serial-2/20190301.as-rel2.txt.bz2
Connected to 127.0.0.1:1234
```

###### Add prefixes created from BGP data using the [script](https://gitlab.inet.tu-berlin.de/thorben/transitive_closure_cone/blob/master/bin/gzipped_prefixes_pairs_from_stdin.py) from the [transitive_closure_cone](https://gitlab.inet.tu-berlin.de/thorben/transitive_closure_cone), for example.

```bash
./build/cc -m client -p data/20190301-prefixes.gz
Connected to 127.0.0.1:1234
```

###### Start classification process

```bash
./build/cc -m client -i data/ -o /tmp -s "sflow.*\.pcap" -M data/mac_mapping.txt
Connected to 127.0.0.1:1234

finish writing /tmp/sflow.gz
active:0 finish:1
start write stats
```

###### Inspect results

```bash
zcat /tmp/sflow.gz | head
0,unknown,192.168.1.3,192.168.1.2,001f297ad132,001cc447d3f9,6,36875,60565,tcp,unknown,70,64,300,1,1,1302306318,{;;ack;dyn-ports:}
0,unknown,192.168.1.3,192.168.1.2,001f297ad132,001cc447d3f9,6,36875,60565,tcp,unknown,70,64,300,1,1,1302306318,{;;ack;dyn-ports:}
0,unknown,192.168.1.3,192.168.1.2,001f297ad132,001cc447d3f9,6,36875,60565,tcp,unknown,70,64,300,1,1,1302306318,{;;ack;dyn-ports:}
0,unknown,192.168.1.3,192.168.1.2,001f297ad132,001cc447d3f9,6,36875,60565,tcp,unknown,70,64,300,1,1,1302306318,{;;ack;dyn-ports:}
0,unknown,192.168.1.3,192.168.1.2,001f297ad132,001cc447d3f9,6,36875,60565,tcp,unknown,70,64,300,1,1,1302306318,{;;ack;dyn-ports:}
0,unknown,192.168.1.3,192.168.1.2,001f297ad132,001cc447d3f9,6,36875,60565,tcp,unknown,70,64,300,1,1,1302306318,{;;ack;dyn-ports:}
0,unknown,192.168.1.3,192.168.1.2,001f297ad132,001cc447d3f9,6,36875,60565,tcp,unknown,70,64,300,1,1,1302306318,{;;ack;dyn-ports:}
0,unknown,192.168.1.3,192.168.1.2,001f297ad132,001cc447d3f9,6,36875,60565,tcp,unknown,70,64,300,1,1,1302306318,{;;ack;dyn-ports:}
1,bogon,192.168.1.2,192.168.1.3,001cc447d3f9,001f297ad132,6,60565,36875,tcp,generic_payload,1518,64,300,1,1,1302306318,{;ack:;36875}
1,bogon,192.168.1.2,192.168.1.3,001cc447d3f9,001f297ad132,6,60565,36875,tcp,generic_payload,1518,64,300,1,1,1302306318,{;ack:;36875}
```

Our sample flow file contains only traffic from a local network, so packets are only classified as unknown and bogon.

###### Inspect stats file

```bash
zcat /tmp/stats.json.gz | python -m json.tool
{
    "traffic-classes": {
        "bogon": {
            "stats": {
                "pkts": 1170300,
                "fraction_all": 0.66626815
            },
            "protocols": {
                "tcp": {
                    "stats": {
                        "pkts": 1170300,
                        "fraction_class": 1.0,
                        "fraction_all": 0.66626815
                    },
 .....
```



###### Use the `client_stdin` mode

```bash
echo "8.8.8.8,680\n8.8.8.8,15169" | ./build/cc -m client_stdin -C
Connected to 127.0.0.1:1234

8.8.8.8,680:invalid
8.8.8.8,15169:regular
```

