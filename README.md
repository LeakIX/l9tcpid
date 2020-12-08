# l9tcpid

[![GitHub Release](https://img.shields.io/github/v/release/LeakIX/l9tcpid)](https://github.com/LeakIX/l9tcpid/releases)
[![Follow on Twitter](https://img.shields.io/twitter/follow/leak_ix.svg?logo=twitter)](https://twitter.com/leak_ix)

l9tcpid takes hosts ( by IP ) from stdin in l9format ( try ip4scout as input ? ) and identifies 
the socket protocol and capabilities :


## Content

-   [Features](#features)
-   [Usage](#usage)
-   [Installation Instructions](#installation-instructions)
    -   [From Binary](#from-binary)
    -   [From Source](#from-source)
-   [Running l9tcpid](#running-l9tcpid)
    -   [l9format](#l9format)
    -   [Running with ip4scout](#running-with-ip4scout)
    -   [Running with nmap](#running-with-nmap)
    -   [Running with masscan](#running-with-masscan)
    -   [Complex example](#complex-example)
    
## Features

- Identifies SSL/TLS connection and details connection + certificate state
- Grab JARM fingerprint ( including upgraded connection from STARTTLS/AUTH TLS )
- Gets a banner
- Tries to identify protocol from that banner
- TODO: defaults to default port/software mapping

## Usage

```sh
▶ l9tcpid service -h
```

Displays help for the service command (only implementation atm)

|Flag           |Description  |
|-----------------------|-------------------------------------------------------|
|--max-threads          |Maximum number of threads used for identification
|--debug          |Prints developer information for now



## Installation Instructions

### From Binary

The installation is easy. You can download the pre-built binaries for your platform from the [Releases](https://github.com/LeakIX/l9tcpid/releases/) page.

```sh
▶ chmod +x l9tcpid-linux-64
▶ mv l9tcpid-linux-64 /usr/local/bin/l9tcpid
```

### From Source

```sh
▶ GO111MODULE=on go get -u -v github.com/LeakIX/l9tcpid/cmd/l9tcpid
▶ ${GOPATH}/bin/l9tcpid service -h
```

## Running l9tcpid

### l9format

l9tcpid speaks [l9format](https://github/LeakIX/l9format). [l9filter](https://github/LeakIX/l9filter) can be used to manage 
input/output from this module.

### Running with ip4scout

```sh 
▶ ip4scout random -r 10000 -p 3306|l9tcpid service --max-threads=100|l9filter transform -i l9 -o human
IP: 163.197.193.175, PORT:3306, PROTO:mysql, SSL:false
mysql_native_password

Raw connection:
00000000  4e 00 00 00 0a 35 2e 35  2e 36 32 2d 6c 6f 67 00  |N....5.5.62-log.|
....

IP: 103.57.220.151, PORT:3306, PROTO:mysql, SSL:false
mysql_native_password

Raw connection:
00000000  65 00 00 00 0a 35 2e 35  2e 35 2d 31 30 2e 33 2e  |e....5.5.5-10.3.|
...

IP: 45.150.6.240, PORT:3306, PROTO:http, SSL:false
HTTP/1.1 400 Bad Request
Server: squid/4.10
.....

Raw connection:
00000000  48 54 54 50 2f 31 2e 31  20 34 30 30 20 42 61 64  |HTTP/1.1 400 Bad|
```

### Running with masscan

```sh
▶ masscan --rate 100000 -p1-65535 192.168.1.0/24|l9filter transform -i masscan -o l9|l9tcpid service --max-threads=10
```

### Running with nmap

```sh 
▶ nmap 192.168.1.0/24 -p80  -T insane -oG -|l9filter transform -i nmap -o l9|l9tcpid service --max-threads=100|l9filter transform -i l9 -o human
```

### Complex example

One can also use JQ to filter results :

```sh 
▶ ./ip4scout random -r 10000 -p 443,587,21|./l9tcpid service --max-threads=100 |tee services.json|jq -c 'select(.ssl.certificate.domain != null)'|jq -r '.ssl.certificate.domain[]'
```

- Scan random host on port 443,587 and 21
- Try to connect to synack ones and upgrade to SSL if possible
- Tee the output to services.json for later usage
- JQ to select services with domains in their SSL certificate
- Display domains

This single command provides a continuous flux of random domains and subdomains found in certs over HTTP, FTP and SMTP connections.

## Thanks

- [hdmoore & RumbleDiscovery](https://github.com/RumbleDiscovery/jarm-go) (Golang JARM library)