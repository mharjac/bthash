# bthash
Utility for extracting BitTorrent hashes from network traffic.

## Installation
Clone bthash repository:
```
git clone https://github.com/mharjac/bthash
```
Install requirements:
```
pip3 install -r requirements.txt
```
## Usage
Extract hashses from a PCAP file:
```
./bthash -f pcap_example/demo.pcap
````
Extract hashses from live network traffic:
```
./bthash -i eth0
```
You can c/p extracted hashes to Google to find out what is downloaded ([example](https://www.google.com/search?q=5a8ce26e8a19a877d8ccc927fcc18e34e1f5ff67)).
