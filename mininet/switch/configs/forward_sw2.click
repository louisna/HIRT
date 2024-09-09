require(library common.click)

define( $intif sw2-eth0,
        $extif sw2-eth1,
        $nofwfec 0,
	$nobwfec 0,
        $noencap 0,
	$doprint 0,
	$nofakefec 0,
        $fastfec 1,
        $windowsize 10,
        $alpha 0.80,
        $beta 0.50,
        $maxcpudec 2,
        $rsspp false,
	$isuniformdrop 0,
	$udroprate 0.03,
	$reta 512,
	$stats false,
        $windowstep -1,
        $minimalsystemdec 0,
	$fecdelay 1,
        $rules /users/TomB/workspace/Fast-SRv6-FEC/rules,
	$scale share,
	$rxdesc 1024,
	$txdesc 1024,
	$maxload 80,
	);

enc :: IP6SRv6FECEncode(ENC fc00::9, DEC fc00::a, REPAIR $nofakefec, FASTFEC $fastfec, WINDOW $windowsize, ALPHA $alpha, BETA $beta, STATS $stats, WINDOWSTEP $windowstep, DELAY_US $fecdelay, MAXLOAD $maxload);

//From internal to external
fd1  :: FromDevice($intif, SNIFFER false, PROMISC true);
td1  :: Queue -> ToDevice($extif);
fd1
    -> SetTimestamp(PER_BATCH true)
    -> pr1 :: Print(INT, -1, ACTIVE  $doprint)
    -> rssc :: AggregateCounterVector(MASK 511)
    -> overhead_counter_packet ::CounterMP(NO_RATE true)
    -> in1 :: InputEncap($intif, 0:0:0:0:0:13, 0:0:0:0:0:12, babe:2::8, $noencap, fc00::a, fc00::9)
    -> IP6SRDecap(FORCE_DECAP false)

    -> tf :: TimestampAccumMP()
    //-> senc :: {
    //    [0] -> s :: Switch($nobwfec);
    //        s[0] 
    //             -> enc :: IP6SRv6FECEncode(ENC fc00::9, DEC fc00::a, REPAIR $nofakefec, FASTFEC $fastfec, WINDOW $windowsize) -> [0];
    //        s[1] -> [0];
    //        input[1] -> [1]enc;
    //}
    -> sFEC :: Switch($nobwfec);
    sFEC[0] -> [0]enc
    -> cFEEDBACKOUT :: Classifier(24/FC00000000000000000000000000000B,-);
    cFEEDBACKOUT[1]
    -> overhead_dec :: Counter(NO_RATE true)
    -> outIE :: Output(0:0:0:0:0:13, 0:0:0:0:0:12, 0x86DD)
    -> StoreAnno(OFFSET 4, ANNO PAINT)
    -> pr1out :: Print(INTOUT, -1, ACTIVE $doprint)
    -> td1 ;
cFEEDBACKOUT[0] -> Print(FEEDBACKDROP, -1, ACTIVE  $doprint) -> Discard;
sFEC[1] -> outIE;
Idle -> [1]enc;


//From external to internal
fd2  :: FromDevice($extif, SNIFFER false, PROMISC true);
td2  :: Queue -> ToDevice($intif);
fd2 
    -> pr2 :: Print(EXT, -1, ACTIVE  $doprint)
    -> in2 :: InputDecap($extif, 0:0:0:0:0:3, 0:0:0:0:0:4, babe:3::2)
    -> Print("EXT-IP6", -1, ACTIVE  $doprint)
    -> Print(ENCAP, -1, ACTIVE $doprint)
    -> {
        [0] -> s :: Switch($noencap);
                s[0] -> IP6SRDecap(FORCE_DECAP false) -> [0];
                s[1] -> [0];
    }
    -> cFeedback :: Classifier(24/FC00000000000000000000000000000B,-);
    cFeedback[1]
    -> sdec :: {
        [0] -> s :: Switch($nofwfec);
            s[0] -> dec :: IP6SRv6FECDecode(FED fc00::b, ENC fc00::a, DEC fc00::9, RECOVER $nofakefec, MINIMALSYSTEMDEC $minimalsystemdec, MAXLOAD $maxload) -> [0];
            s[1] -> [0];
	dec[1] -> [1];
    }
    -> pr2out :: Print(EXT-OUT, -1, ACTIVE $doprint)
    -> cREPAIR :: Classifier(24/FC00000000000000000000000000000A,-);
cREPAIR[1]
-> {
       [0] -> s :: Switch($noencap);  
		s[0] -> IP6SRDecap(FORCE_DECAP true) -> [0];
        	s[1] -> [0];
   }
   // -> IP6Print("Decaped")
    -> Output(0:0:0:0:0:3, 0:0:0:0:0:4, 0x86DD)
    -> Print(SORTIE, -1, ACTIVE  $doprint)
    -> td2 ;
cREPAIR[0] -> Discard;
cFeedback[0] -> Print(FEEDBACK, -1, ACTIVE $doprint) -> [1]enc;
sdec[1] -> outIE;

in1[1] -> td2;
in2[1] -> td1;

DriverManager(wait,
		read fd1.xstats,
		read fd2.xstats,
		print "RESULT-ENCODERLATAVG $(tf.average_time)",
		print "RESULT-ENCODERLATTIME $(tf.time)",
		print "RESULT-ENCODERLATCOUNT $(tf.count)",
		print "RESULT-DECODERFW_DROPPED $(fd2.hw_dropped)",
		print "RESULT-DECODERFW_COUNT $(fd2.hw_count)",
		print "RESULT-DECODERFW_TXCOUNT $(td2.count)",
		print "RESULT-ENCODERBW_DROPPED $(fd1.hw_dropped)",
		print "RESULT-ENCODERBW_COUNT $(fd1.hw_count)",
		print "RESULT-ENCODERBW_TXCOUNT $(td1.count)",
                print "RESULT-OVERHEAD_DECODER $(overhead_dec.count)",
                print "RESULT-NB-PACKETS-INGRESS $(overhead_counter_packet.count)"

)	

//DeviceBalancer(METHOD rsspp, DEV fd1, AUTOSCALE false, VERBOSE 1, RSSCOUNTER rssc, CPUS $maxcpuenc, MARK true, GROUP true, RETA_SIZE 512, ACTIVE $rsspp );


//Script(TYPE ACTIVE,
//	set time $(now),
//	read load,
//	print "DEC-$time-RESULT-LOAD $(add $(load))",
//	print "DEC-$time-RESULT-MAXLOAD $(max $(load))",
//	wait 1s,
//	loop

//);
