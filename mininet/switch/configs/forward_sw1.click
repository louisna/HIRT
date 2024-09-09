require(library common.click)
define( $intif sw1-eth0,    
        $extif sw1-eth1,
        $nofwfec 0,
        $nobwfec 0,
        $noencap 0,
        $doprint 0,
        $nofakefec 1,
        $fastfec 1,
	$windowsize 10,
	$alpha 0.80,
        $beta 0.50,
        $isuniformdrop 0,
	$udroprate 0.03,
	$reta 512,
	$stats false,
        $windowstep -1,
        $minimalsystemdec 0,
	$fecdelay 1,
	$scale share,
	$rxdesc 1024,
	$txdesc 1024,
	$maxload 80,
	$prefetch false,
	$clone true,
	$fast true,
    );

enc :: IP6SRv6FECEncode(ENC fc00::a, DEC fc00::9, REPAIR $nofakefec, FASTFEC $fastfec, WINDOW $windowsize, ALPHA $alpha, BETA $beta, STATS $stats, WINDOWSTEP $windowstep, DELAY_US $fecdelay, MAXLOAD $maxload);

//From internal to external
fd1  :: FromDevice($intif, SNIFFER false, PROMISC true);
td1  :: Queue -> ToDevice($extif);
fd1
    -> rssc :: AggregateCounterVector(MASK 511)
    -> pr1 :: Print(INT, -1, ACTIVE $doprint)
    -> in1 :: InputEncap($intif, 0:0:0:0:0:12, 0:0:0:0:0:13, babe:1::6, $noencap, fc00::9, fc00::a)
    -> IP6SRDecap(FORCE_DECAP false)
    -> Print(TEST, -1, ACTIVE $doprint)
    -> sFEC :: Switch($nofwfec);
    sFEC[0] -> [0]enc
    -> ap1 :: Print(INT-AP, -1, ACTIVE $doprint)
    -> o :: Output(0:0:0:0:0:12, 0:0:0:0:02:01, 0x86DD)
    -> StoreAnno(OFFSET 4, ANNO PAINT)
    -> ap111 :: Print(INT-AP, -1, ACTIVE $doprint)
    -> td1;
sFEC[1] -> ap1; // Other branch is also forwarded
Idle -> [1]enc;

fd2 :: FromDevice($extif, SNIFFER false, PROMISC true);
td2 :: Queue -> ToDevice($intif);
fd2
//	-> Print(EXT, CPU true)
    -> pr2 :: Print(EXT, -1, ACTIVE $doprint)
    -> ctr1 :: CounterMP(NO_RATE true)
    -> in2 :: InputDecap($extif, 0:0:0:0:0:2, 0:0:0:0:0:1, babe:3::1)
    -> IP6Print(EXT-IP6, ACTIVE $doprint)
    -> {
        [0] -> s :: Switch($noencap);
                s[0] -> IP6SRDecap(FORCE_DECAP false) -> [0];
                s[1] -> [0];
    }
    -> Print(AVANTLECLASSIFIER, -1, ACTIVE false)
    -> cFeedback :: Classifier(24/FC00000000000000000000000000000B,-);
    cFeedback[1]
    -> ctr2 :: CounterMP(NO_RATE true)
    -> sdec :: {
        [0] -> s :: Switch($nobwfec);
            s[0] -> dec :: IP6SRv6FECDecode(FED fc00::b, ENC fc00::9, DEC fc00::a, RECOVER $nofakefec, MINIMALSYSTEMDEC $minimalsystemdec, MAXLOAD $maxload, PREFETCH $prefetch, CLONE $clone, FAST $fast) -> [0];
            s[1] -> [0];
	dec[1] -> [1];
    }
    -> cREPAIR :: Classifier(24/FC000000000000000000000000000009,-);
cREPAIR[1]
 -> {
        [0] -> s :: Switch($noencap);  
 		s[0] -> IP6SRDecap(FORCE_DECAP true) -> [0];
		s[1] -> [0];
    }
    // Print recovered packets
    -> {
        [0] -> cRecovered :: Classifier(7/33, -)
                -> Print(RECOVERED, -1, ACTIVE $doprint) -> [0];
        cRecovered[1] -> [0];
    }
    -> overhead_counter_packet ::CounterMP(NO_RATE true) 
    -> Output(0:0:0:0:0:2, 0:0:0:0:0:1, 0x86DD)
    -> {
		[0] -> cRecoveredAfter :: Classifier(21/33,-)
			-> [0];
                cRecoveredAfter[1] -> [0];
	}
    -> td2 ;

cFeedback[0] -> Print(FEEDBACK, -1, ACTIVE $doprint) -> [1]enc;
cREPAIR[0] -> Discard;
sdec[1] -> o;
in1[1] -> td2;
in2[1] -> td1;

// sdec[1] -> td2;

DriverManager(wait,
		read fd1.xstats,
		read fd2.xstats,
                print "RESULT-ENCODERFW_DROPPED $(fd1.hw_dropped)",
                print "RESULT-ENCODERFW_COUNT $(fd1.hw_count)",
                print "RESULT-ENCODERFW_TXCOUNT $(td1.count)",
                print "RESULT-DECODERFW_TXDROPPED $(td1.dropped)",
                print "RESULT-DECODERBW_SKIPPED $(sdec/dec.skipped)",
                print "RESULT-DECODERBW_OVERLOAD $(sdec/dec.overload)",
                print "RESULT-DECODERBW_REPAIRBS $(sdec/dec.repair_before_source)",

                print "RESULT-DECODERBW_COUNT $(fd2.hw_count)",
                print "RESULT-DECODERBW_TXCOUNT $(td2.count)",
                print "RESULT-DECODERBW_TXDROPPED $(td2.dropped)",
                print "RESULT-DECODERBW_DROPPED $(fd2.hw_dropped)",
                print "RESULT-DECODERBW_CYCLES_0 $(useful_kcycles $maxcpuenc)",
                print "RESULT-DECODERBW_CYCLES_0_PP $(div $(mul 1000 $(useful_kcycles $maxcpuenc) ) $(fd2.xstats rx_q0packets) )",
                print "RESULT-OVERHEAD_PACKET $(overhead_counter_packet.count)",
		print "RESULT-CTR1 $(ctr1.count)",
		print "RESULT-CTR2 $(ctr2.count)",
                )

//Script(TYPE ACTIVE,
//        set time $(now),
//	read load,
//        print "ENC-$time-RESULT-LOAD $(add $(load))",
//        print "ENC-$time-RESULT-MAXLOAD $(max $(load))",
//        wait 1s,
//        loop
//);