elementclass IP6Input{
    input
    -> Strip(14)
	-> checkip :: CheckIP6Header(PROCESS_EH true)
        -> l :: LookupIP6Route(ff02::2/128 ::0 1, ::0/0 ::0 0)
	// -> DecIP6HLIM()
    -> output;

    l[1] -> IP6Print("Router broadcast discarded...") -> Discard();
};

elementclass InputDecap { $port, $src, $dst, $ip6src |

	input
	-> c :: Classifier(12/86dd 20/3a 54/87, 12/86DD, 12/0027, -);

	c[0]
	-> MarkIP6Header(OFFSET 14)
	-> IP6Print("NDP $ip6src $src")
	-> IP6NDAdvertiser($ip6src $src)

	-> IP6Print("NDPOUT")
	-> [1]output;

	c[1]
    	-> IP6Input()
	-> output;

	c[2] -> Print("STP")-> Discard;
    c[3] -> Print("Non-IPv6", -1) -> Discard;
};



elementclass InputEncap { $port, $src, $dst, $ip6src, $noencap, $encapa, $encapb |
    input
	-> c :: Classifier(12/86dd 20/3a 54/87, 12/86DD, 12/0800, 12/0806, 12/0027,-);

	c[0]
	-> MarkIP6Header(OFFSET 14)
	-> IP6Print("E-NDP $ip6src $src")
	-> IP6NDAdvertiser($ip6src $src) 

	-> MarkIP6Header(OFFSET 14)
	-> IP6Print("E-NDPOUT")
-> [1]output;

	c[1]
	//-> Print("IP6 from $port", -1)
	-> IP6Input()
	    -> {
		[0] -> s :: Switch($noencap);
		    s[0] -> IP6SREncap(ADDR $encapa, ADDR $encapb, ENCAP_DST true) -> [0];
		    s[1] -> [0];
	    }	
	-> output;

    c[2] -> Print("IPv4 (discarded)")
	-> Strip(14)
	-> CheckIPHeader()
	-> Discard;

    c[3] -> Print("ARP (discarded)")
	-> Discard;
	c[4] -> Print("STP") -> Discard;

    c[5] -> Print("Non-IPv6", 256) -> Discard;
};


elementclass Output { $src, $dst, $proto |
	input
		-> EtherEncap($proto, SRC $src, DST $dst)
		// -> EtherEncap(0x86DD, SRC $src, DST $dst)
		-> output;
};

// http :: HTTPServer(PORT 8080);
// StaticThreadSched(http -1);