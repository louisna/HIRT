define (
    $extif h1-eth0,
    $rate 100, // Number of packets per second.
    $udplength 500, // Payload of the packet. Must be sufficient to store the selective repeat.
    $limit 1000, // Number of UDP packets to send.
)

source :: RatedSource(DATA 0x111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111, HEADROOM 500, RATE $rate, LIMIT $limit);
udp :: UDPIP6Encap(babe:1::5, 6788, babe:2::5, 6789);
eth :: EtherEncap(0x86DD, 0:0:0:0:0:15, 0:0:0:0:0:13);
td :: Queue -> ToDevice($extif);


source -> udp -> eth -> td;