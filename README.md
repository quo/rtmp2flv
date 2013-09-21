rtmp2flv
========

Tool to extract FLV video from unencrypted RTMP streams.

Capture streams using something like:

    tcpdump -B 8192 -vnpi eth0 -s 0 tcp src port 1935 -w rtmp.pcap

Then use tcpflow to extract the TCP streams:

    tcpflow -T %T_%A%C%c.rtmp -r rtmp.pcap

Finally, convert the streams to FLV files:

    ./rtmp2flv.py *.rtmp

This works best when you've captured the entire stream, including the initial handshake. If the dump starts in the middle of an RTMP stream, you will have to specify --chunksize and possibly --skip.

License: Public domain
