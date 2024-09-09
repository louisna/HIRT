// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_FROMMINDUMP_HH
#define CLICK_FROMMINDUMP_HH
#include <click/batchelement.hh>
#include <click/task.hh>
#include <click/timer.hh>
#include <click/notifier.hh>
#include <click/ipflowid.hh>
#include <click/fromfile.hh>
#include <click/handlercall.hh>
CLICK_DECLS

/**

=c
FromMinDump(FILENAME [,STOP, ACTIVE, BURST, VERBOSE, LIMIT, TIMES, LOOP_CALL, DPDK])

=s traces
 Replay a trace generated by ToMinDump
=d
Keywords:
=over 8

=item FILENAME
The file to read

=item STOP
Whether the router should be stopped when the trace is finished. Default is false.

=item BURST
Burst size. Default is 32.

=item VERBOSE
Print more messages about the status. Default is 0.

=item LIMIT
Read at most LIMIT packets. Default is -1: no limit.

=item TIMES
Loop over the file TIMES time. Default is 1: read one the whole file. -1 to loop forever.

=item LOOP_CALL
A handler to call on each loop, e.g. a Script to print a message. Default is disabled.

=item DPDK
Force the generation of DPDK packets

=a ToMinDump, FromIPSummaryDump

=e

FromMinDump(packets.mindump, DPDK 1, STOP 1)
-> EtherEncap(0x800, a:a:a:a:a:a, b:b:b:b:b:b)
-> ToDPDKDevice(0)

*/

class FromMinDump : public BatchElement{ public:

    FromMinDump() CLICK_COLD;
    ~FromMinDump() CLICK_COLD;

    const char *class_name() const override	{ return "FromMinDump"; }
    const char *port_count() const override	{ return PORTS_0_1; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    int initialize(ErrorHandler *) CLICK_COLD;
    void cleanup(CleanupStage) CLICK_COLD;
    void add_handlers() CLICK_COLD;

    bool run_task(Task *);

    // From binary data to packet
    Packet *read_packet(ErrorHandler *, uint8_t * buffer);
    // A wrapper to the above
    Packet *get_packet(bool push= true);
    // Wrapper to fread
    inline int read_binary_line(uint8_t * buffer);
    inline char * read_string_line(char* s);
    // Wrapper to fseek
    inline int go_to_first_packet();
    // Check if we are allowed to go back to the beginning,
    // return 1 in case of success
    inline bool fileRewind();

    Packet *pull(int) override;
#if HAVE_BATCH
    PacketBatch *pull_batch(int,unsigned) override;
#endif
    void run_timer(Timer *timer);

  private:

    bool _dpdk;
    int _times;
    int _first_packet;
    int _active;
    int _stop;
    int _verbose;
    int64_t _limit;
    int64_t _this_limit;
    Task _task;
    ActiveNotifier _notifier;
    HandlerCall * _loop_trigger_h;
    Timer _timer;
    String _filename;
    FILE * _f;
    int _iterations;
    uint8_t * _file_data;
    size_t _file_size;
    size_t _file_pos;

    int _minor_version;
    unsigned _burst;

    static String read_handler(Element *, void *) CLICK_COLD;
    static int write_handler(const String &, Element *, void *, ErrorHandler *) CLICK_COLD;

};

CLICK_ENDDECLS
#endif
