gobbler - "Eating it's way through your pcap files"
=======

Gobbler was written to allow you to take a pcap file and import into a number of different services.

Currently there is support for importing into Splunk (via TCP or UDP listener) and printing to screen as JSON.

To use Gobbler all you need to specify is your pcap file and choice of output.

For example:

./gobbler -p pcap/test.pcap -u splunk

The gobbler.conf file holds the settings you will need to change to make.

[splunk]
server = 'localhost'
port = 10000
protocol = 'udp'

This is still in it's early development and more protocol parsers and upload options will be added over time.

