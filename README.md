# l9tcpid

l9tcpid takes hosts ( by IP ) from stdin in l9format ( try ip4scout as input ?) and identifies 
the socket protocol and capabilities :

- Identifies SSL/TLS connection and details connection + certificate state
- Grab JARM fingerprint ( including upgraded connection from STARTTLS/AUTH TLS )
- Gets a banner
- Tries to identify protocol from that banner
- TODO: defaults to default port/software mapping

## TODO

Documentation :)