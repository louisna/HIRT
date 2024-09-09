#ifndef CLICK_UDPIPTUNNEL_HH
#define CLICK_UDPIPTUNNEL_HH
#include <clicknet/udp.h>

#include <click/atomic.hh>
#include <click/batchelement.hh>
#include <click/glue.hh>
CLICK_DECLS

/*
=c

UDPIPTunnel(SRC, DST)

TODO

*/

class UDPIPTunnel : public BatchElement {
   public:
    UDPIPTunnel() CLICK_COLD;
    ~UDPIPTunnel() CLICK_COLD;

    const char *class_name() const override { return "UDPIPTunnel"; }
    const char *port_count() const override { return "2/2"; }

    int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
    void add_handlers() CLICK_COLD;

    void push(int, Packet *) override;
#if HAVE_BATCH
    void push_batch(int, PacketBatch *) override;
#endif
    void encap(Packet *, std::function<void(Packet *)> push);
    void decap(Packet *, std::function<void(Packet *)> push);


   protected:
    struct in_addr _saddr;
    struct in_addr _daddr;
    uint16_t _sport;
    uint16_t _dport;
    bool _cksum;

   private:
    bool _use_dst_anno;
#if HAVE_FAST_CHECKSUM && FAST_CHECKSUM_ALIGNED
    bool _aligned;
    bool _checked_aligned;
#endif
    atomic_uint32_t _id;

    static String read_handler(Element *, void *) CLICK_COLD;
};

CLICK_ENDDECLS
#endif  // CLICK_UDPIPTUNNEL_HH