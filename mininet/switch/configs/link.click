//Non-dropping, 10ms link for testing. The NPF script generates this by itself

define( $port0 0000:41:00.0,
	$port1 0000:41:00.1,
	$doprint 0);

fd1 :: FromDPDKDevice($port0, VERBOSE 10, SCALE PARALLEL, PROMISC 1, MAXTHREADS 1)
    -> Print(LEFT, ACTIVE $doprint)
    -> q1 :: Queue(65536)
    -> lu1 :: LinkUnqueue(LATENCY 10ms, BANDWIDTH 0)
    -> ac1 :: AverageCounter()
    -> EtherRewrite(SRC 00:00:00:00:02:02, DST 00:00:00:00:03:01)
    -> ToDPDKDevice($port1);

fd2 :: FromDPDKDevice($port1, VERBOSE 10, SCALE PARALLEL, PROMISC 1, MAXTHREADS 1)
    -> Print(RIGHT, ACTIVE $doprint)
    -> sdrop :: {
        [0] -> s :: Switch(0);
            s[0] -> [0];
            s[1] -> Print(DROPPACKET, -1, ACTIVE false) -> drop :: IP6Drop(ADDR fc00::9, ADDR babe:1::5, UNIFORM 0, UDROPRATE 0.08, K 0.99, P 0.05, R 0.5, H 0.1) -> [0];
    }
    -> q2  :: Queue(65536)
    -> lu2 :: LinkUnqueue(LATENCY 10ms, BANDWIDTH 0)
    -> ac2 :: AverageCounter()
    -> EtherRewrite(SRC 00:00:00:00:02:01, DST 00:00:00:00:01:01)
    -> ToDPDKDevice($port0);

StaticThreadSched(fd2 1, lu2 1);

DriverManager(	wait, 
		print "RESULT-LINKHWDROPPED $(add $(fd1.hw_dropped) $(fd2.hw_dropped))",
		print "RESULT-LINKSWDROPPED $(add $(q1.drops) $(q2.drops))",
		print "RESULT-LINKFWLINKRATE $(ac1.link_rate)",
		print "RESULT-LINKBWLINKRATE $(ac2.link_rate)",
)
