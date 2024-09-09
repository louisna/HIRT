/*
 * ip6encap.{cc,hh} -- element encapsulates packet in IP6 header
 * Louis Navarre
 * Tom Barbette
 *
 * Copyright (c) 2021 IP Networking Lab, UCLouvain
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "ip6srv6fec.hh"
#include <click/nameinfo.hh>
#include <click/confparse.hh>
#if HAVE_DPDK
#include <click/dpdkdevice.hh>
#endif
#include <clicknet/ether.h>
#include <click/error.hh>
#include <click/glue.hh>
#define MAX(a, b) ((a > b) ? a : b)
#define MIN(a, b) ((a < b) ? a : b)

#if SYMBOL_USE_FAST_LIBRARY
extern "C"
{
#include <moepgf/moepgf.h>
    extern struct moepgf gflib;
}
#endif

#if SYMBOL_USE_FAST_LIBRARY
struct moepgf gflib;
#endif

CLICK_DECLS

uint16_t inline my_min(uint16_t a, uint16_t b)
{
    return ((a < b) ? a : b);
}

uint16_t inline my_max(uint16_t a, uint16_t b)
{
    return ((a > b) ? a : b);
}

IP6SRv6FECEncode::IP6SRv6FECEncode()
{
} 

IP6SRv6FECEncode::~IP6SRv6FECEncode()
{
    static_assert(sizeof(source_tlv_t) == 8, "source_tlv_t should be 8 bytes");

    for (int i = 0; i < _state.weight(); i++)
    {
        auto &s = _state.get_value(i);

        for (int i = 0; i < SRV6_FEC_BUFFER_SIZE_ENC; ++i)
        {
            Packet *packet = s.rlc_info.source_buffer[i];
            if (packet)
            {
                packet->kill();
            }
        }
    }
    if (total_rs > 0) 
    {
        click_chatter("RESULT-RS-GENERATED %lu", total_rs);
    }
    click_chatter("Total received %u", total_received);
}

int IP6SRv6FECEncode::configure(Vector<String> &conf, ErrorHandler *errh)
{
    auto &s = *_state;
    int delay;
    if (Args(conf, this, errh)
            .read_mp("ENC", enc)
            .read_mp("DEC", dec)
            .read_or_set("WINDOW", _max_window_size, 20)
            .read_or_set("SCHEME", _fec_scheme, SRV6_FEC_RLC)
            .read_or_set("REPAIR", _send_repair, true)
            .read_or_set("FASTFEC", _fast_fec, true)
            .read_or_set("ALPHA", _alpha, 0.75)
            .read_or_set("BETA", _beta, 0.0)
            .read_or_set("STATS", _extended_stats, false)
            .read_or_set("WINDOWSTEP", _window_step, -1)
            .read_or_set("DELAY_US", delay, 1)
            .read_or_set("MAXLOAD", _maxload, 80)
            .read_or_set("CLONE", _clone, true)
            .complete() < 0)
        return -1;
    fed = IP6Address("fc00::b");
    click_chatter("WHICH should send repair use: %u", _send_repair);

    click_chatter("USE FASTFEC:%u", _fast_fec);
    // TODO: remove and automatize
    router()->get_root_init_future()->post(this);
    total_rs = 0;
    total_received = 0;
    _delay = Timestamp::make_usec(delay);
    if (delay == 0)
        assert(!_delay);
    general_loss = (uint64_t)(0.05 * GRANULARITY);
    return 0;
}

void IP6SRv6FECEncode::static_initialize()
{
    click_gf256_init();
}

#define _timer_interval 100

int IP6SRv6FECEncode::solve_initialize(ErrorHandler *errh)
{
    for (int i = 0; i < _state.weight(); i++)
    {
        IP6SRv6FECEncode::State &s = _state.get_value(i);

        // Preset the IPv6 Header
        memset(&s.repair_ip6, 0, sizeof(click_ip6));
        memcpy(&s.repair_ip6.ip6_src, enc.data(), sizeof(IP6Address));
        memcpy(&s.repair_ip6.ip6_dst, dec.data(), sizeof(IP6Address));
        s.repair_ip6.ip6_flow = htonl(6 << IP6_V_SHIFT);
        s.repair_ip6.ip6_plen = 0; // Will be completed by the repair FEC Scheme
        s.repair_ip6.ip6_nxt = IPPROTO_ROUTING;
        s.repair_ip6.ip6_hlim = 53;

        // Preset the SRv6 Header
        memset(&s.repair_srv6, 0, sizeof(click_ip6_sr));
        s.repair_srv6.type = IP6PROTO_SEGMENT_ROUTING;
        s.repair_srv6.segment_left = 1;
        s.repair_srv6.last_entry = 1;
        s.repair_srv6.flags = 0;
        s.repair_srv6.tag = 0;
        s.repair_srv6.ip6_sr_next = 253;
        s.repair_srv6.ip6_hdrlen = (sizeof(repair_tlv_t) + 2 * sizeof(IP6Address)) / 8;

        memset(&s.rlc_info, 0, sizeof(rlc_info_t));
        rlc_fill_muls(_rlc_params.muls);
        s.rlc_info.prng = rlc_reset_coefs();

        s.set_thread_id(i);

        // Feedback information
        s.rlc_info.loss_estimation = 0.01;
        s.rlc_info.threshold_loss = 0.0005;
        s.rlc_info.loss_burst_mean = 5;
        s.rlc_info.loss_burst_std_dev = 0.0;
        s.rlc_info.min_step = 1;

        // Feedback information new version.
        s.rlc_info.loss_mean_per_window = (_max_window_size / 20) + 1.0;
        s.rlc_info.loss_std_per_window = 0.0;

        s.timer = new Timer(this);
        s.timer->initialize(this);

        s.timer->move_thread(i);
        s.timer->schedule_after_msec(_timer_interval);
    }

    return Router::InitFuture::solve_initialize(errh);
}

void IP6SRv6FECEncode::push(int input, Packet *p_in)
{
    if (input == SRV6_FEC_FEEDBACK_INPUT)
    {
        feedback_message(p_in, [this](Packet *p)
                         { output(0).push(p); });
    }
    else
    {
        abort(); //TODO XXX
    }
}

void IP6SRv6FECEncode::run_timer(Timer* timer)
{
    auto &s = *_state;
    auto t = master()->thread(click_current_cpu_id());
    int thresh = (t->load_max_scale() * _maxload) / 100;
    
    if (t->load_unscaled() > thresh) {
        int high_thresh = (t->load_max_scale() * (_maxload + 100)/2) / 100;  
        if (s.rlc_info.min_step >= _max_window_size + 10)
            s.rlc_info.min_step = _max_window_size + 10;
        else {
            if (t->load_unscaled() > high_thresh)
                s.rlc_info.min_step = max(10,s.rlc_info.min_step * 2);
            else
                s.rlc_info.min_step++;
        }
        //click_chatter("[%d] Performance limit, augmenting minimal step to %d", click_current_cpu_id(), s.rlc_info.min_step);
    } else if (t->load_unscaled() < thresh - 10) {
        s.rlc_info.min_step = max(1,s.rlc_info.min_step-1);
    }
    if (click_current_cpu_id() == 12)
        click_chatter("%f -> %d -> %d", t->load(), s.rlc_info.min_step, total_rs);
    timer->reschedule_after_msec(_timer_interval);
}


#if HAVE_BATCH
void IP6SRv6FECEncode::push_batch(int input, PacketBatch *batch)
{
    //click_chatter("PUSH [%d] -> %d", click_current_cpu_id(), _state->get_stream_id());
    if (input == SRV6_FEC_FEEDBACK_INPUT)
    {
        EXECUTE_FOR_EACH_PACKET_ADD(feedback_message, batch);
    }
    else
    {
        auto &s = *_state;
        Timestamp now = Timestamp::now();
        PacketList nb;
        FOR_EACH_PACKET_SAFE(batch, p) {
            int err;
            err = IP6SRv6FECEncode::fec_scheme(p, now, nb, s.builder);
            if (err < 0)
            {
                click_chatter("FEC STOPPED");
                return;
            }
        }

        if (_delay) {
            while (!s.builder.empty() && s.builder.front()->timestamp_anno() < now) {
                nb.append(s.builder.pop_front());
            }
        }//Todo : set timer
        output_push_batch(0, nb.finish());
    }
}
#endif

String
IP6SRv6FECEncode::read_handler(Element *e, void *thunk)
{
    return "<error>";
}

void IP6SRv6FECEncode::add_handlers()
{
    add_read_handler("src", read_handler, 0, Handler::CALM);
    add_write_handler("src", reconfigure_keyword_handler, "1 SRC");
    add_read_handler("dst", read_handler, 1, Handler::CALM);
    add_write_handler("dst", reconfigure_keyword_handler, "2 DST");
}

inline int
IP6SRv6FECEncode::fec_scheme(Packet *p_in, Timestamp now, PacketList &batch, PacketList &delayed)
{
    auto &s = *_state;

    // Complete the source TLV
    s.source_tlv.type = TLV_TYPE_FEC_SOURCE;
    s.source_tlv.len = sizeof(source_tlv_t) - 2; // Ignore type and len
    s.source_tlv.padding = 0;
    s.source_tlv.stream_id = s.get_stream_id();
    s.source_tlv.sfpid = s.rlc_info.encoding_symbol_id;

    // According to RFC8681, we should add the TLV in the FEC Framework and not the FEC Scheme
    // but we do it here to improve the performance (we avoid to make a different copy of the same packet)
    WritablePacket *p = srv6_fec_add_source_tlv(p_in, &s.source_tlv);
    if (!p)
    {
        return -1; // Memory problem, packet is already destroyed
    }

    // Store packet as source symbol
    store_source_symbol(p, s.rlc_info.encoding_symbol_id);

    // Update RLC information
    ++s.rlc_info.encoding_symbol_id;

    // Increase the window if possible, otherwise we slide it by one
    if (s.rlc_info.window_size < _max_window_size)
    {
        ++s.rlc_info.window_size;
    }
    // TODO: wrapping
    if (s.rlc_info.encoding_symbol_id - s.rlc_info.esi_last_as_reset > _max_window_size)
    {
        s.rlc_info.esi_last_as_reset = s.rlc_info.encoding_symbol_id;
        s.rlc_info.added_repair = 0;
    }

    batch.append(p);

    // if (s.rlc_info.min_step >= _max_window_size) {
    //     click_chatter("Ici que ca merde %d %d", s.rlc_info.min_step, _max_window_size);
    //     return 0;
    // }
    // Generate a repair symbol if full window
    if (should_send_repair(s))
    {
        int err = do_repair_symbols(s);
        if (err < 0)
            return -1;
        assert(s.repair_packet);
        encapsulate_repair_payload(s, s.repair_packet, &s.repair_tlv, s.rlc_info.max_length);

        if (_delay) {
            s.repair_packet->set_timestamp_anno(now + _delay);
            delayed.append(s.repair_packet);
        } else {
            batch.append(s.repair_packet);
        }
        s.repair_packet = 0;

        // Reset parameters of the RLC information
        s.rlc_info.max_length = 0;
        memset(&s.repair_tlv, 0, sizeof(repair_tlv_t));
        s.rlc_info.prng = rlc_reset_coefs();
        return 1;
    }
    return 0;
}

inline void
IP6SRv6FECEncode::store_source_symbol(Packet *p_in, uint32_t encoding_symbol_id)
{
    auto &s = *_state;
    // Free previous packet at the same place in the buffer
    Packet *previous_packet = s.rlc_info.source_buffer[encoding_symbol_id % SRV6_FEC_BUFFER_SIZE_ENC];
    if (previous_packet)
    {
        previous_packet->kill();
    }
    total_received++;
#if HAVE_DPDK
if (likely(_clone)) {
    s.rlc_info.source_buffer[encoding_symbol_id % SRV6_FEC_BUFFER_SIZE_ENC] = p_in->clone(true);
    // The problem with shared() being false is that the packet will be recylable
    // free_pkt_empty will prevent the packet to go in the pool
    s.rlc_info.source_buffer[encoding_symbol_id % SRV6_FEC_BUFFER_SIZE_ENC]->set_buffer_destructor(DPDKDevice::free_pkt_empty);
    p_in->set_buffer_destructor(DPDKDevice::free_pkt_empty);
} else
#endif
{

    s.rlc_info.source_buffer[encoding_symbol_id % SRV6_FEC_BUFFER_SIZE_ENC] = p_in->clone();
}
}

inline void
IP6SRv6FECEncode::rlc_encode_symbols(State &s, uint32_t encoding_symbol_id)
{
    tinymt32_t prng = s.rlc_info.prng;
    tinymt32_init(&prng, s.rlc_info.repair_key);
    // tinymt32_init(&prng, 1);
    // encoding_symbol_id: of the last source symbol (i.e. of the repair symbol)
    uint32_t start_esid = encoding_symbol_id - s.rlc_info.window_size + 1;
    for (int i = 0; i < s.rlc_info.window_size; ++i)
    {
        uint16_t idx = (start_esid + i) % SRV6_FEC_BUFFER_SIZE_ENC;
        Packet *source_symbol = s.rlc_info.source_buffer[idx];
        rlc_encode_one_symbol(source_symbol, s.repair_packet, &prng, _rlc_params.muls, &s.repair_tlv);
    }
}

void IP6SRv6FECEncode::xor_encode_symbols(State &s, uint32_t encoding_symbol_id)
{

    uint32_t start_esid = encoding_symbol_id - s.rlc_info.window_size + 1;
    for (int i = 0; i < s.rlc_info.window_size; ++i)
    {
        uint16_t idx = (start_esid + i) % SRV6_FEC_BUFFER_SIZE_ENC;
        Packet *source_symbol = s.rlc_info.source_buffer[idx];

        xor_encode_one_symbol(source_symbol, s.repair_packet, &s.repair_tlv);
    }
}

void IP6SRv6FECEncode::xor_encode_one_symbol(Packet *s, WritablePacket *r, repair_tlv_t *repair_tlv)
{
    // Leave room for the IPv6 Header, SRv6 Header (3 segments) and repair TLV
    uint8_t repair_offset = 40 + 8 + 16 * 2 + sizeof(repair_tlv_t);
    uint8_t *s_64 = (uint8_t *)s->data();
    uint8_t *r_64 = (uint8_t *)(r->data() + repair_offset);

    for (uint16_t i = 0; i < s->length() / sizeof(uint8_t); ++i)
    {
        r_64[i] ^= s_64[i];
    }

    // Also code the potential remaining data
    uint8_t *s_8 = (uint8_t *)s->data();
    uint8_t *r_8 = (uint8_t *)(r->data() + repair_offset);
    for (uint16_t i = (s->length() / sizeof(uint8_t)) * sizeof(uint8_t); i < s->length(); ++i)
    {
        r_8[i] ^= s_8[i];
    }

    // Encode the packet length
    uint16_t coded_length = repair_tlv->coded_length;
    repair_tlv->coded_length ^= s->length();
}

void IP6SRv6FECEncode::rlc_encode_one_symbol(Packet *s, WritablePacket *r, tinymt32_t *prng, uint8_t muls[256 * 256 * sizeof(uint8_t)], repair_tlv_t *repair_tlv)
{
    // Leave room for the IPv6 Header, SRv6 Header (3 segments) and repair TLV
    uint8_t repair_offset = 40 + 8 + 16 * 2 + sizeof(repair_tlv_t);

    // Get coefficient for this source symbol
    uint8_t coef = 1; // Hidden

    uint16_t packet_length = s->length(); // Cast in uint16_t because 16 bits for IPv6 packet length

    // Encode the packet in the repair symbol
    symbol_add_scaled(r->data() + repair_offset, coef, s->data(), packet_length, muls);

    // Encode the packet length
    uint16_t coded_length = repair_tlv->coded_length;
    symbol_add_scaled_safe(&coded_length, coef, &packet_length, sizeof(uint16_t), muls);
    repair_tlv->coded_length = coded_length;
}

WritablePacket *IP6SRv6FECEncode::srv6_fec_add_source_tlv(Packet *p_in, source_tlv_t *tlv)
{
    const click_ip6 *ip6 = reinterpret_cast<const click_ip6 *>(p_in->data());
    const click_ip6_sr *srv6 = (const click_ip6_sr *)ip6_find_header(ip6, IP6_EH_ROUTING, p_in->end_data());
    if (!srv6)
    {
        p_in->kill();
        // click_chatter("Not an SRv6 packet!");
        return 0;
    }

    unsigned srv6_offset = (unsigned char *)srv6 - (unsigned char *)ip6;

    // Extend the packet to add the TLV
    WritablePacket *p = p_in->push(sizeof(source_tlv_t));
    if (!p)
        return 0;

    uint16_t srv6_len = 8 + srv6->ip6_hdrlen * 8;

    // Move headers and add TLV
    memmove(p->data(), p->data() + sizeof(source_tlv_t), srv6_len + srv6_offset);
    memcpy(p->data() + sizeof(click_ip6) + srv6_len, tlv, sizeof(source_tlv_t));

    // Update the new length of the SRv6 Header
    click_ip6_sr *srv6_update = reinterpret_cast<click_ip6_sr *>(p->data() + srv6_offset);
    srv6_update->ip6_hdrlen += sizeof(source_tlv_t) / 8;
    click_ip6 *ip6_update = reinterpret_cast<click_ip6 *>(p->data());
    ip6_update->ip6_plen = htons(ntohs(ip6_update->ip6_plen) + sizeof(source_tlv_t));
    p->set_network_header(p->data(), srv6_offset + srv6_len + sizeof(source_tlv_t));
    SET_PAINT_ANNO(p, tlv->stream_id);

    return p;
}

void IP6SRv6FECEncode::encapsulate_repair_payload(State &s, WritablePacket *p, repair_tlv_t *tlv, uint16_t packet_length)
{

    // IPv6 and SRv6 Header pointer
    assert(p);
    click_ip6 *r_ip6 = reinterpret_cast<click_ip6 *>(p->data());
    click_ip6_sr *r_srv6 = reinterpret_cast<click_ip6_sr *>(p->data() + sizeof(click_ip6));
    repair_tlv_t *r_tlv = reinterpret_cast<repair_tlv_t *>(p->data() + sizeof(click_ip6) + 8 + 32);
    // IPv6 Header
    memcpy(r_ip6, &s.repair_ip6, sizeof(click_ip6));
    r_ip6->ip6_plen = htons(packet_length + sizeof(click_ip6_sr) + sizeof(repair_tlv_t) + 2 * sizeof(IP6Address));
    // SRv6 Header
    memcpy(r_srv6, &s.repair_srv6, sizeof(click_ip6_sr));
    memcpy(&r_srv6->segments[0], enc.data(), sizeof(IP6Address));
    memcpy(&r_srv6->segments[1], dec.data(), sizeof(IP6Address));
    // Add repair TLV
    memcpy(r_tlv, tlv, sizeof(repair_tlv_t));
    // Set annotations
    p->set_network_header(p->data(), sizeof(click_ip6) + sizeof(click_ip6_sr) + sizeof(repair_tlv_t) + 2 * sizeof(IP6Address));
    SET_PAINT_ANNO(p, tlv->stream_id);
}

void IP6SRv6FECEncode::feedback_message(Packet *p_in, std::function<void(Packet *)> push)
{

    const click_ip6 *ip6 = reinterpret_cast<const click_ip6 *>(p_in->data());
    const click_ip6_sr *srv6 = reinterpret_cast<const click_ip6_sr *>(p_in->data() + sizeof(click_ip6));
    const feedback_tlv_t *tlv = reinterpret_cast<const feedback_tlv_t *>(p_in->data() + sizeof(click_ip6) + sizeof(click_ip6_sr) + (srv6->last_entry + 1) * 16);
    int stream_id = tlv->stream_id;
    // auto &s = _state.get_value_for_thread(State::stream_id_to_threadid(stream_id));
    // TODO: this does not work for starlink. But we must change with commented line above
    // for multi threading.
    auto &s = *_state;

    // Compute the mean loss per active window of the feedback.
    if (tlv->used_window_size != _max_window_size) {
        return;
    }

    if (tlv->nb_active_windows == 0) {
        return; // No loss.
    }

    // Moving average of the loss estimations per window.
    double loss_mean_feedback = tlv->total_losses / (double)tlv->nb_active_windows;
    s.rlc_info.loss_mean_per_window = _alpha * s.rlc_info.loss_mean_per_window + (1.0 - _alpha) * loss_mean_feedback;
    double mean_squared_n = tlv->total_losses / (double)tlv->nb_active_windows;
    double loss_var_feedback = (tlv->total_losses_squared / (double)tlv->nb_active_windows) - mean_squared_n * mean_squared_n;
    if (loss_var_feedback > 0) {
        double loss_std_feedback = sqrt(loss_var_feedback);
        s.rlc_info.loss_std_per_window = _alpha * (s.rlc_info.loss_std_per_window) + (1.0 - _alpha) * loss_std_feedback;
    }
}

#define SYMBOL_FAST 1

#define ALIGNMENT 32
static CLICK_ALWAYS_INLINE size_t align(size_t val)
{
    return (val + ALIGNMENT - 1) / ALIGNMENT * ALIGNMENT;
}

static CLICK_ALWAYS_INLINE size_t align_below(size_t val)
{
    size_t retval = align(val);
    if (retval > 0 && retval != val)
    {
        retval -= ALIGNMENT;
    }
    return retval;
}

inline CLICK_ALWAYS_INLINE void
IP6SRv6FECEncode::symbol_add_scaled_safe(void *symbol1, uint8_t coef, const void *symbol2, uint32_t symbol_size, uint8_t *mul)
{
    // Hidden.
}

/**
 * @brief Take a symbol and add another symbol multiplied by a
 *        coefficient, e.g. performs the equivalent of: p1 += coef * p2
 * @param[in,out] p1     First symbol (to which coef*p2 will be added)
 * @param[in]     coef  Coefficient by which the second packet is multiplied
 * @param[in]     p2     Second symbol
 */
inline CLICK_ALWAYS_INLINE void
IP6SRv6FECEncode::symbol_add_scaled(void *symbol1, uint8_t coef, const void *symbol2, uint32_t symbol_size, uint8_t *mul)
{
    if (_fast_fec)
    {
        uint8_t *s1 = (uint8_t *)symbol1;
        uint8_t *s2 = (uint8_t *)symbol2;
        size_t aligned_size = align_below(symbol_size); // Size until multiple of 32 bytes
        if (aligned_size > 0)
        {
            gflib.maddrc(s1, s2, coef, aligned_size);
        }

        // Compute the remaining using byte-per-byte method
        size_t remaining = symbol_size - aligned_size;
        // click_chatter("Safe with: %u", remaining);
        symbol_add_scaled_safe(s1 + aligned_size, coef, symbol2 + aligned_size, remaining, mul);
    }
    else
    {
        symbol_add_scaled_safe(symbol1, coef, symbol2, symbol_size, mul);
    }
}

inline CLICK_ALWAYS_INLINE bool
IP6SRv6FECEncode::symbol_is_zero(void *symbol, uint32_t symbol_size)
{
    uint8_t *data8 = (uint8_t *)symbol;
    uint64_t *data64 = (uint64_t *)symbol;
    for (int i = 0; i < symbol_size / 8; i++)
    {
        if (data64[i] != 0)
            return false;
    }
    for (int i = (symbol_size / 8) * 8; i < symbol_size; i++)
    {
        if (data8[i] != 0)
            return false;
    }
    return true;
}

void IP6SRv6FECEncode::click_gf256_init()
{
#if SYMBOL_USE_FAST_LIBRARY
    moepgf_init(&gflib, MOEPGF256, MOEPGF_ALGORITHM_BEST);
#endif
}

bool IP6SRv6FECEncode::should_send_repair(State &s)
{
    // This is used if we want to enforce some window step.
    if (_window_step != -1)
    {
        if (_window_step <= s.rlc_info.encoding_symbol_id - s.rlc_info.last_sent_repair_esi)
        {
            s.rlc_info.last_sent_repair_esi = s.rlc_info.encoding_symbol_id;
            return true;
        }
    }

    if (s.rlc_info.loss_mean_per_window <= s.rlc_info.threshold_loss)
    {
        return false;
    }

    uint32_t gap_since_last = s.rlc_info.encoding_symbol_id - s.rlc_info.last_sent_repair_esi;
    double estimated_loss_per_window = s.rlc_info.window_size / (double)(s.rlc_info.loss_mean_per_window + _beta * s.rlc_info.loss_std_per_window);
    if (gap_since_last >= estimated_loss_per_window) {
        s.rlc_info.last_sent_repair_esi = s.rlc_info.encoding_symbol_id;
        return true;
    }

    return false;
}

int IP6SRv6FECEncode::do_repair_symbols(State &s)
{
    // Compute maximum payload length
    // TODO: ERROR comes from here
    // Decrement by 1 because ID was incremented in the previous call
    uint32_t start_esid = s.rlc_info.encoding_symbol_id - 1 - s.rlc_info.window_size + 1;
    for (int i = 0; i < s.rlc_info.window_size; ++i)
    {
        uint16_t idx = (start_esid + i) % SRV6_FEC_BUFFER_SIZE_ENC;
        assert(s.rlc_info.source_buffer[idx]);
        s.rlc_info.max_length = MAX(s.rlc_info.max_length, s.rlc_info.source_buffer[idx]->length());
    }
    total_rs++;
    // Create new repair packet with correct size
    s.repair_packet = Packet::make(s.rlc_info.max_length + sizeof(click_ip6) + sizeof(click_ip6_sr) + sizeof(repair_tlv_t) + 2 * sizeof(IP6Address));
    if (!s.repair_packet)
    {
        return -1;
    }

    memset(s.repair_packet->data(), 0, s.repair_packet->length());

    // Encode the source symbols in repair
    if (_fec_scheme == SRV6_FEC_RLC)
    {
        rlc_encode_symbols(s, s.source_tlv.sfpid);
    }
    else
    {
        xor_encode_symbols(s, s.source_tlv.sfpid);
    }
    // Complete the Repair FEC Payload ID
    s.repair_tlv.type = TLV_TYPE_FEC_REPAIR;
    s.repair_tlv.len = sizeof(repair_tlv_t) - 2;
    s.repair_tlv.padding = _fec_scheme;
    s.repair_tlv.rfpid = s.source_tlv.sfpid;
    s.repair_tlv.rfi = ((s.rlc_info.window_size << 24) + (0 << 16)) + s.rlc_info.repair_key;
    assert(s.repair_tlv.nss <= _max_window_size);
    // assert(_max_window_size <= 30);
    s.repair_tlv.nss = s.rlc_info.window_size;
    s.repair_tlv.stream_id = s.get_stream_id();
    // assert(s.repair_tlv.stream_id - 32 < 5);
    // Update RLC informations after repair
    ++s.rlc_info.repair_key;
    assert(s.repair_packet);
    return 0;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IP6SRv6FECEncode)
ELEMENT_MT_SAFE(IP6SRv6FECEncode)
#if SYMBOL_USE_FAST_LIBRARY
ELEMENT_LIBS(-lmoepgf)
#endif
