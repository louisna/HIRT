/*
 * ip6srv6fecdecode.{cc,hh} -- Forward Erasure Correction module for IPv6 Segment Routing (VacLink)
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
#include "ip6srv6fecdecode.hh"
#include <click/nameinfo.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/batchbuilder.hh>
#if HAVE_DPDK
#include <click/dpdkdevice.hh>
#endif
#include <cmath>
#define MAX(a, b) ((a > b) ? a : b)
#define MIN(a, b) ((a < b) ? a : b)

#if SYMBOL_USE_FAST_LIBRARY
extern "C"
{
#include <moepgf/moepgf.h>
    extern struct moepgf gflib_dec;
}
#endif

#if SYMBOL_USE_FAST_LIBRARY
struct moepgf gflib_dec;
#endif

CLICK_DECLS

IP6SRv6FECDecode::IP6SRv6FECDecode()
{
    assign_inv(_rlc_params.table_inv);
}

IP6SRv6FECDecode::~IP6SRv6FECDecode()
{
    if (total_recovered > 0)
    {
    	click_chatter("total recoverec: %u", total_recovered);
   	    click_chatter("Total bad recovered: %u", total_bad_recovered);
    	click_chatter("RESULT-RECOVERED %.5f", (double)total_recovered);
    	click_chatter("RESULT-SUCCESSDECODE %.7f", ((double)total_system_done) / ((double)total_system_tried));
    	click_chatter("RESULT-TOTALSYSTEMTRIED %u", total_system_tried);
    	click_chatter("Total recu normalement: %u", total_received_source);
    }

}

int IP6SRv6FECDecode::configure(Vector<String> &conf, ErrorHandler *errh)
{
    if (Args(conf, this, errh)
            .read_mp("ENC", enc)
            .read_mp("DEC", dec)
            .read_mp("FED", feedback)
            .read_or_set("RECOVER", _do_recover, true)
	        .read_or_set("MINIMALSYSTEMDEC", _minimal_system_fec, false)
            .read_or_set("MAXLOAD", _maxload, 80)
            .read_or_set("PREFETCH", _prefetch, false)
            .read_or_set("FAST", _use_fast, true)
            .read_or_set("CLONE", _clone, true)
            .read_or_set("ECN", _use_ecn, false)
            .complete() < 0)
        return -1;

#ifndef HAVE_DPDK_PACKET_POOL
    errh->warning("To have good performance with FEC, you need to compile with --enable-dpdk-pool !!!");
#endif
if (_prefetch)
    errh->warning("Old PREFETCH parameter ignored : it did not help");
    total_recovered = 0;
    total_received_source = 0;
    total_bad_recovered = 0;
    total_system_tried = 0;
    total_system_done = 0;
    int max_streams = 256;
    _state.resize(max_streams);

    for (int i = 0; i < _state.size(); i++)
    {
        auto &s = _state[i];
        s.last_window = 200;
        s.white_srv6 = (click_ip6_sr *)CLICK_LALLOC(sizeof(click_ip6_sr) + 3 * sizeof(IP6Address) + sizeof(source_tlv_t));
        // Complete it with pseudo values to ensure that we recover a "working" SRH
        s.white_srv6->type = IP6PROTO_SEGMENT_ROUTING;
        s.white_srv6->tag = 0;
        s.white_srv6->ip6_sr_next = 0;
        s.white_srv6->flags = 0;
        s.white_srv6->segment_left = 0;
        s.white_srv6->last_entry = 2;
        s.white_srv6->ip6_hdrlen = 7;
        memset(&s.white_srv6->segments[1], 0, sizeof(IP6Address));
        memset(&s.white_srv6->segments[2], 0, sizeof(IP6Address));
        memset(&s.white_srv6->segments[0], 0, sizeof(IP6Address));

        // TLV
        uint8_t *ptr_srv6 = (uint8_t *)s.white_srv6;
        ptr_srv6 += 8 + sizeof(IP6Address) * 3;
        memset(ptr_srv6, 0, sizeof(source_tlv_t));
        s.white_srv6_total_length = sizeof(click_ip6_sr) + 3 * sizeof(IP6Address) + sizeof(source_tlv_t);
        memcpy(&s.white_srv6->segments[1], dec.data(), sizeof(IP6Address));
        memcpy(&s.white_srv6->segments[2], enc.data(), sizeof(IP6Address));

	s.esi_last_in_sequence = -1; // Set preceding 0 as init
    }

    router()->get_root_init_future()->post(this);

    return 0;
}

int IP6SRv6FECDecode::solve_initialize(ErrorHandler *errh)
{
    for (int i = 0; i < _state.size(); i++)
    {

        auto &s = _state[i];

        memset(&s.rlc_info, 0, sizeof(rlc_info_decoder_t));
        memset(&s.rlc_feedback, 0, sizeof(srv6_fec2_feedback_t));
        s.rlc_feedback.esid_last_feedback = 0;
        memset(s.rlc_feedback.packet_trace, false, sizeof(bool) * FEEDBACK_BUFFER_LENGTH);

        // Malloc once the utils for the RLC recovering scheme
        s.rlc_utils.ss_array = (srv6_fec2_source_t **)CLICK_LALLOC(sizeof(srv6_fec2_source_t *) * SRV6_RLC_MAX_SYMBOLS);
        memset(s.rlc_utils.ss_array, 0, sizeof(srv6_fec2_source_t *) * SRV6_RLC_MAX_SYMBOLS);

        s.rlc_utils.rs_array = (srv6_fec2_repair_t **)CLICK_LALLOC(sizeof(srv6_fec2_repair_t *) * RLC_MAX_WINDOWS);
        memset(s.rlc_utils.rs_array, 0, sizeof(srv6_fec2_repair_t *) * RLC_MAX_WINDOWS);

        s.rlc_utils.x_to_source = (uint16_t *)CLICK_LALLOC(sizeof(uint16_t) * SRV6_RLC_MAX_SYMBOLS);
        memset(s.rlc_utils.x_to_source, 0, sizeof(uint16_t) * SRV6_RLC_MAX_SYMBOLS);
        s.rlc_utils.source_to_x = (uint16_t *)CLICK_LALLOC(sizeof(uint16_t) * SRV6_RLC_MAX_SYMBOLS);
        memset(s.rlc_utils.source_to_x, 0, sizeof(uint16_t) * SRV6_RLC_MAX_SYMBOLS);

        s.rlc_utils.protected_symbols = (bool *)CLICK_LALLOC(sizeof(bool) * SRV6_RLC_MAX_SYMBOLS);
        memset(s.rlc_utils.protected_symbols, 0, sizeof(bool) * SRV6_RLC_MAX_SYMBOLS);

        // This is not optimal as it should be the "maximum window size"
        s.rlc_utils.coefs = (uint8_t *)CLICK_LALLOC(sizeof(uint8_t) * SRV6_RLC_MAX_SYMBOLS);
        memset(s.rlc_utils.coefs, 0, sizeof(uint8_t) * SRV6_RLC_MAX_SYMBOLS);
        // Are memset really usefull at this stage?

        s.rlc_utils.unknowns = (srv6_fec2_term_t **)CLICK_LALLOC(sizeof(srv6_fec2_term_t *) * SRV6_RLC_MAX_SYMBOLS);
        memset(s.rlc_utils.unknowns, 0, sizeof(srv6_fec2_term_t *) * SRV6_RLC_MAX_SYMBOLS);
        s.rlc_utils.system_coefs = (uint8_t **)CLICK_LALLOC(sizeof(uint8_t *) * RLC_MAX_WINDOWS);
        memset(s.rlc_utils.system_coefs, 0, sizeof(uint8_t *) * RLC_MAX_WINDOWS);
        s.rlc_utils.constant_terms = (srv6_fec2_term_t **)CLICK_LALLOC(sizeof(srv6_fec2_term_t *) * SRV6_RLC_MAX_SYMBOLS);
        memset(s.rlc_utils.constant_terms, 0, sizeof(srv6_fec2_term_t *) * SRV6_RLC_MAX_SYMBOLS);
        s.rlc_utils.undetermined = (bool *)CLICK_LALLOC(sizeof(bool) * SRV6_RLC_MAX_SYMBOLS);
        memset(s.rlc_utils.undetermined, 0, sizeof(bool) * SRV6_RLC_MAX_SYMBOLS);

        for (int i = 0; i < RLC_MAX_WINDOWS; ++i)
        {
            s.rlc_utils.system_coefs[i] = (uint8_t *)CLICK_LALLOC(sizeof(uint8_t) * SRV6_RLC_MAX_SYMBOLS);
            memset(s.rlc_utils.system_coefs[i], 0, sizeof(uint8_t) * SRV6_RLC_MAX_SYMBOLS);
        }
    }
    return Router::InitFuture::solve_initialize(errh);
}

void IP6SRv6FECDecode::cleanup(CleanupStage stage)
{
    for (int j = 0; j < _state.size(); j++)
    {

        auto &s = _state[j];
        for (int i = 0; i < SRV6_FEC_BUFFER_SIZE; ++i)
        {

            srv6_fec2_source_t *packet = s.rlc_info.source_buffer[i];
            if (packet)
            {
                packet->p->kill();
                CLICK_LFREE(packet, sizeof(srv6_fec2_source_t));
            }
            srv6_fec2_repair_t *repair = s.rlc_info.repair_buffer[i];
            if (repair)
            {
                repair->p->kill();
                CLICK_LFREE(repair, sizeof(srv6_fec2_repair_t));
            }
            srv6_fec2_source_t *recovered = s.rlc_info.recovd_buffer[i];
            if (recovered)
            {
                recovered->p->kill();
                CLICK_LFREE(recovered, sizeof(srv6_fec2_source_t));
            }
        }

        // Free all utils from RLC system
        CLICK_LFREE(s.rlc_utils.ss_array, sizeof(srv6_fec2_source_t *) * SRV6_RLC_MAX_SYMBOLS);
        CLICK_LFREE(s.rlc_utils.rs_array, sizeof(srv6_fec2_repair_t *) * RLC_MAX_WINDOWS);
        CLICK_LFREE(s.rlc_utils.x_to_source, sizeof(uint16_t) * SRV6_RLC_MAX_SYMBOLS);
        CLICK_LFREE(s.rlc_utils.source_to_x, sizeof(uint16_t) * SRV6_RLC_MAX_SYMBOLS);
        CLICK_LFREE(s.rlc_utils.protected_symbols, sizeof(bool) * SRV6_RLC_MAX_SYMBOLS);
        CLICK_LFREE(s.rlc_utils.coefs, sizeof(uint8_t) * SRV6_RLC_MAX_SYMBOLS);
        CLICK_LFREE(s.rlc_utils.unknowns, sizeof(srv6_fec2_term_t *) * SRV6_RLC_MAX_SYMBOLS);
        CLICK_LFREE(s.rlc_utils.constant_terms, sizeof(srv6_fec2_term_t *) * SRV6_RLC_MAX_SYMBOLS);
        CLICK_LFREE(s.rlc_utils.undetermined, sizeof(bool) * SRV6_RLC_MAX_SYMBOLS);
        for (int i = 0; i < RLC_MAX_WINDOWS; ++i)
        {
            CLICK_LFREE(s.rlc_utils.system_coefs[i], sizeof(uint8_t) * SRV6_RLC_MAX_SYMBOLS);
        }
        CLICK_LFREE(s.rlc_utils.system_coefs, sizeof(uint8_t *) * RLC_MAX_WINDOWS);

        CLICK_LFREE(s.white_srv6, sizeof(click_ip6_sr));
    }
}

void IP6SRv6FECDecode::static_initialize()
{
    click_gf256_init();
}

void IP6SRv6FECDecode::push(int, Packet *p_in)
{
    click_chatter("OLD PUSH");
    fec_framework(p_in, [this](Packet *p)
                  { output(0).push(p); });
}

#if HAVE_BATCH
void IP6SRv6FECDecode::push_batch(int, PacketBatch *batch)
{

    //click_chatter("[%d] Received %d packets", click_current_cpu_id(), batch->count());
    EXECUTE_FOR_EACH_PACKET_ADD(fec_framework, batch);
    if (batch)
    {
        output_push_batch(0, batch);
    }
}
#endif

String
IP6SRv6FECDecode::read_handler(Element *e, void *thunk)
{
    IP6SRv6FECDecode* fed = (IP6SRv6FECDecode*)e;
    switch ((uintptr_t)thunk)
    {
    case 2: {
        uint64_t skipped = 0;
        for (int i = 0; i < fed->_state.size(); i ++) {
            skipped += fed->_state[i].repair_skipped;
        }
        return String(skipped);
        break;}
    case 3: {
        uint64_t overload = 0;
        for (int i = 0; i < fed->_state.size(); i ++) {
            overload += fed->_state[i].repair_overload;
        }
        return String(overload);
        break;
    }
    case 4: {
        uint64_t repair_before_source = 0;
        for (int i = 0; i < fed->_state.size(); i ++) {
            repair_before_source += fed->_state[i].repair_before_source;
        }
        return String(repair_before_source);
        break;
    }
    }
    return "<error>";
}

void IP6SRv6FECDecode::add_handlers()
{
    add_read_handler("src", read_handler, 0, Handler::CALM);
    add_write_handler("src", reconfigure_keyword_handler, "1 SRC");
    add_read_handler("dst", read_handler, 1, Handler::CALM);
    add_write_handler("dst", reconfigure_keyword_handler, "2 DST");
    add_read_handler("skipped", read_handler, 2);
    add_read_handler("overload", read_handler, 3);
    add_read_handler("repair_before_source", read_handler, 4);
}

void IP6SRv6FECDecode::fec_framework(Packet *p_in, std::function<void(Packet *)> push)
{
    // Manipulate modified packet because we will remove the TLV
    Packet *p = p_in;
    const click_ip6 *ip6 = reinterpret_cast<const click_ip6 *>(p->data());
    const click_ip6_sr *srv6 = reinterpret_cast<const click_ip6_sr *>(p->data() + sizeof(click_ip6));
    int err;
    // Find TLV: source or repair symbol
    uint8_t tlv_type = 0;
    // last_entry is 0-indexed => +1
    uint16_t start_tlv_offset = 8 + (srv6->last_entry + 1) * 16;
    // ip6_hdrlen does not include the 8 first bytes => + 1
    uint16_t total_tlv_size = (srv6->ip6_hdrlen + 1) * 8 - start_tlv_offset;
    uint16_t read_bytes = 0;
    uint8_t *tlv_ptr;
    while (read_bytes < total_tlv_size)
    { 
        // Iterate over all TLVs of the SRH
        tlv_ptr = (uint8_t *)srv6 + start_tlv_offset + read_bytes;
        if (tlv_ptr[0] == TLV_TYPE_FEC_SOURCE || tlv_ptr[0] == TLV_TYPE_FEC_REPAIR)
        {
            tlv_type = tlv_ptr[0];
            break;
        }
        read_bytes += tlv_ptr[1];
        if (tlv_ptr[1] == 0)
        {
            click_chatter("ERROR : malformed TLV");
            p->kill();
            return;
        }
    }

    // Not a source or repair symbol
    if (tlv_type != TLV_TYPE_FEC_SOURCE && tlv_type != TLV_TYPE_FEC_REPAIR)
    {
        push(p);
        // click_chatter("Should not: %u", tlv_type);
        return;
    }
    int _sid = ((source_tlv_t *)tlv_ptr)->stream_id - 32;
    auto &s = _state[_sid];

    // click_chatter("%d-%d", sid, ((source_tlv_t *)tlv_ptr)->sfpid);
    if (tlv_type == TLV_TYPE_FEC_SOURCE)
    {
        // Load TLV locally
        source_tlv_t source_tlv;
        memcpy(&source_tlv, tlv_ptr, sizeof(source_tlv_t));

        // Remove the TLV from the source packet
        // We do not remove the TLV to improve performance (we do not make a different copy of the same packet)
        // remove_tlv_source_symbol(p, tlv_ptr - p->data()); // Cleaner way?

        // Update the most recent max ESI
        // TODO: wrapping
        s.rlc_feedback.most_recent_esi = source_tlv.sfpid;

        // Call FEC Scheme
        fec_scheme_source(p, &source_tlv, s, push);

        if (unlikely(s.rlc_info.recovd_buffer[source_tlv.sfpid % SRV6_FEC_BUFFER_SIZE] && s.rlc_info.recovd_buffer[source_tlv.sfpid % SRV6_FEC_BUFFER_SIZE]->encoding_symbol_id ==  source_tlv.sfpid))  {
            s.repair_before_source++;
            p->kill();
        } else {
            push(p);
        }
    }
    else
    {
        // Load TLV locally
        repair_tlv_t repair_tlv;
        memcpy(&repair_tlv, tlv_ptr, sizeof(repair_tlv_t));

        // Update the most recent max ESI
        // TODO: wrapping
        if (s.rlc_feedback.most_recent_esi < repair_tlv.rfpid)
        {
            s.rlc_feedback.most_recent_esi = repair_tlv.rfpid;
        }

        // Call FEC Scheme
        fec_scheme_repair(p, &repair_tlv, push, s);
    }

    // TODO: wrap
    if (s.rlc_feedback.most_recent_esi >= FEEDBACK_TIMELAG + s.rlc_feedback.esid_last_feedback)
    {
        rlc_feedback(s, _sid + 32);
        s.rlc_feedback.nb_received = 0;
    }
}

int compare_esi_wrap(uint32_t esi_1, uint32_t esi_2)
{
    // MUST: the difference cannot be higher than (1 << 30)
    if (esi_1 == esi_2)
    {
        return 0;
    }
    else if (((uint32_t)(esi_1 - esi_2)) < (1 << 30))
    {
        return 1;
    }
    else
    {
        return -1;
    }
}

int IP6SRv6FECDecode::fec_scheme_source(Packet *p_in, source_tlv_t *tlv, StreamState &s, std::function<void(Packet *)> push)
{
    p_in->set_network_header(p_in->data());
    p_in->set_network_header_length(40 + 64);

    // received_ss.push_back(tlv->sfpid);
    total_received_ss++;

    // Store packet as source symbol
    store_source_symbol(p_in, tlv, s);
    total_received_source++;
    // Compute feedback information
    if (s.rlc_feedback.last_received_esid_in_sequence + 1 == tlv->sfpid)
    {
        // Received in sequence
        // click_chatter("Received in sequence: the sfpid: %u and last received was %u\n", tlv->sfpid, s.rlc_feedback.last_received_esid_in_sequence);
        ++s.rlc_feedback.last_received_esid_in_sequence;
    }

    // Update the last received ESI in sequence if the current symbol just follows the previous last
    if (s.esi_last_in_sequence + 1 == tlv->sfpid)
    {
        ++s.esi_last_in_sequence;
    }
    else if (((uint32_t)s.esi_last_in_sequence + SRV6_FEC_BUFFER_SIZE) <= tlv->sfpid)
    {
        s.esi_last_in_sequence = tlv->sfpid - SRV6_FEC_BUFFER_SIZE + 1;
    }

    // Was the source symbol considered as lost? i.e. is the last repair symbol "older" than this source symbol?
    if (compare_esi_wrap(tlv->sfpid, s.rlc_info.encoding_symbol_id) <= 0)
    {
        click_chatter("Was lost!");
        // Yes! The source symbol was considered as lost but just arrived later!
        --s.rlc_info.nb_unknowns_last_system;
        if (s.rlc_info.nb_unknowns_last_system > 0 && s.rlc_info.nb_unknowns_last_system <= s.rlc_info.nb_equations_last_system)
        {
            rlc_recover_symbols(push, s);
        }
    }

    return 0;
}

void IP6SRv6FECDecode::fec_scheme_repair(Packet *p_in, repair_tlv_t *tlv, std::function<void(Packet *)> push, StreamState &s)
{
    // Store packet as source symbol
    store_repair_symbol(p_in, tlv, s);
    if (unlikely(!_do_recover))
    {
        return;
    }

    // received_rs.push_back(tlv->rfpid);
    total_received_rs++;
    s.last_window = tlv->nss;

    s.rlc_feedback.last_received_esid_in_sequence = tlv->rfpid;

    auto t = master()->thread(click_current_cpu_id());
    int thresh = (t->load_max_scale() * _maxload) / 100;
    // if (t->load_unscaled() > thresh) {
    //     //Keep this 1024th of packets, exagerated a bit so we throw away packets when at 90%
    //     int k = (t->load_unscaled() - thresh) * 1200 / (1024 - thresh);

    //     //We skip k% of packets

    //     //Sample size is 1024
    //     s.repair_overload++;

    //     if ((k > 0 && k < 512 && (s.repair_overload % (1024/k)) == 0) || k >= 1024 || (k >= 512 && (s.repair_overload % (1024 / (1024 - k))) != 0 )) {
    //         s.repair_skipped++;
    //         if (s.repair_overload % 100000 == 0) {
    //             click_chatter("[%d] %f -> %d -> %d -> SKIPPED (%d mod %d)",click_current_cpu_id(), t->load(), t->load_unscaled(), k, s.repair_overload % (1024/k), (1024/k));
    //         }

    //         return;
    //     }
    //     if (s.repair_overload % 100000 == 0) {
    //         click_chatter("[%d] %f -> %d -> %d -> KEPT",click_current_cpu_id(), t->load(), t->load_unscaled(), k);
    //     }
        
    // }

    // Call RLC recovery
    if (tlv->padding == SRV6_FEC_RLC)
    {
        rlc_recover_symbols(push, s);
    }
    else
    {
        xor_recover_symbols(push, s);
    }
}

inline void
IP6SRv6FECDecode::store_source_symbol(Packet *p_in, source_tlv_t *tlv, StreamState &s)
{
    uint32_t encoding_symbol_id = tlv->sfpid;

    // Store the source symbol
    srv6_fec2_source_t *symbol;
    // Optimization: reuse the previous malloc if available
    srv6_fec2_source_t *previous_symbol = s.rlc_info.source_buffer[encoding_symbol_id % SRV6_FEC_BUFFER_SIZE];
    if (previous_symbol)
    {
        if (previous_symbol->p)
        {
            previous_symbol->p->kill();
            previous_symbol->p = 0;
        }
        symbol = previous_symbol;
    }
    else
    {
        symbol = (srv6_fec2_source_t *)CLICK_LALLOC(sizeof(srv6_fec2_source_t));
    }
    symbol->encoding_symbol_id = tlv->sfpid;

#if HAVE_DPDK
    if (_clone) {
        symbol->p = p_in->clone(true);
        symbol->p->set_buffer_destructor(DPDKDevice::free_pkt_empty);
        p_in->set_buffer_destructor(DPDKDevice::free_pkt_empty);
    } else
#endif
    {
        symbol->p = p_in->clone();
    }
    // Store the current length of the packet
    // This will let us know if the packet changed
    symbol->initial_plen = p_in->length();
    const click_ip6_sr *srv6 = reinterpret_cast<const click_ip6_sr *>(p_in->data() + sizeof(click_ip6));
    symbol->srv6_next_hdr = srv6->ip6_sr_next;
    assert(symbol->initial_plen > 0);
    const click_ip6 *ip6 = reinterpret_cast<const click_ip6 *>(symbol->p->data());
    memcpy(&symbol->dst, &ip6->ip6_dst, sizeof(in6_addr));

    s.rlc_info.source_buffer[encoding_symbol_id % SRV6_FEC_BUFFER_SIZE] = symbol;
    ++s.rlc_feedback.nb_received;
    s.rlc_feedback.packet_trace[encoding_symbol_id % FEEDBACK_BUFFER_LENGTH] = true;
}

void IP6SRv6FECDecode::store_repair_symbol(Packet *p_in, repair_tlv_t *tlv, StreamState &s)
{
    uint32_t encoding_symbol_id = tlv->rfpid;
    // click_chatter("Receive repair symbol %u", encoding_symbol_id);
    // Store the repair symbol
    srv6_fec2_repair_t *symbol;
    // Optimization: reuse the previous malloc if available
    srv6_fec2_repair_t *previous_symbol = s.rlc_info.repair_buffer[encoding_symbol_id % SRV6_FEC_BUFFER_SIZE];
    if (previous_symbol)
    {
        if (previous_symbol->p)
        {
            previous_symbol->p->kill();
            previous_symbol->p = 0;
        }
        symbol = previous_symbol;
    }
    else
    {
        symbol = (srv6_fec2_repair_t *)CLICK_LALLOC(sizeof(srv6_fec2_repair_t));
    }
    memcpy(&symbol->tlv, tlv, sizeof(repair_tlv_t));
    memset(symbol->decoded_ind, 0, sizeof(bool) * MAX_WINDOW_SIZE);
    // assert(symbol->tlv.nss < 34);

    symbol->p = p_in->uniqueify();

    s.rlc_info.repair_buffer[encoding_symbol_id % SRV6_FEC_BUFFER_SIZE] = symbol;
    s.rlc_info.encoding_symbol_id = encoding_symbol_id;
}

void IP6SRv6FECDecode::remove_tlv_source_symbol(WritablePacket *p, uint16_t offset_tlv)
{
    // Update payload length of IPv6 Header and SRv6 Header
    unsigned len = p->network_header_length();
    click_ip6 *ip6 = reinterpret_cast<click_ip6 *>(p->data());
    click_ip6_sr *srv6 = reinterpret_cast<click_ip6_sr *>(p->data() + sizeof(click_ip6));
    ip6->ip6_plen -= htons(sizeof(source_tlv_t));
    srv6->ip6_hdrlen -= 1;

    // Push everything before the TLV, sizeof(tlv) after
    memmove(p->data() + sizeof(source_tlv_t), p->data(), offset_tlv);
    p->pull(sizeof(source_tlv_t));
    p->set_network_header(p->data(), len - sizeof(source_tlv_t));
}

srv6_fec2_term_t *
IP6SRv6FECDecode::init_term(Packet *p, uint16_t offset, uint16_t max_packet_length)
{
    srv6_fec2_term_t *t = (srv6_fec2_term_t *)CLICK_LALLOC(sizeof(srv6_fec2_term_t));
    uint8_t *data = (uint8_t *)CLICK_LALLOC(sizeof(uint8_t) * max_packet_length);
    memcpy(data, p->data() + offset, p->length() - offset);
    t->data = data;
    t->length.coded_length = 0;
    return t;
}

void kill_term(srv6_fec2_term_t *t)
{
    CLICK_LFREE(t->data, t->length.data_length);
    CLICK_LFREE(t, sizeof(srv6_fec2_term_t));
}

void IP6SRv6FECDecode::rlc_recover_symbols(std::function<void(Packet *)> push, StreamState &s)
{
    uint16_t max_packet_length = 0; // decoding size
    uint16_t nb_source_symbols = 0;
    uint16_t window_size = 0;
    uint16_t max_seen_window_size = 0;
    uint32_t encoding_symbol_id = s.rlc_info.encoding_symbol_id; // Of last symbol protected by the received repair symbol
    uint32_t first_esi_last_rs;
    uint8_t stream_id;

    // Maybe this shortcut is too harsh
    // Reset the values of the last system because we start a new one
    s.rlc_info.nb_unknowns_last_system = 0;
    s.rlc_info.nb_equations_last_system = 0;

    // Heuristic: we avoid to look for lost packets to recover if the current
    // repair symbol does not protect any lost source symbol
    // We also compute the feedback information: last received source symbol
    // By receiving this repair symbol, we know that previous lost source symbols that are out of window
    // won't be protected anymore, so we start at the beginning of the window of this repair symbol
    bool useful_repair = false;
    srv6_fec2_repair_t *repair_tmp = s.rlc_info.repair_buffer[encoding_symbol_id % SRV6_FEC_BUFFER_SIZE];
    uint32_t nb_symbols_to_loop = MIN((uint32_t) (repair_tmp->tlv.rfpid - s.esi_last_in_sequence), SRV6_FEC_BUFFER_SIZE);
    uint16_t window_size_tmp = repair_tmp->tlv.nss;
    uint32_t nb_symbols_heuristic = MIN((uint32_t) (repair_tmp->tlv.rfpid - s.esi_last_in_sequence), window_size_tmp);
    uint32_t last_esi = repair_tmp->tlv.rfpid;
    s.rlc_feedback.last_received_esid_in_sequence = repair_tmp->tlv.rfpid;
    // click_chatter("Heuristic gives %u instead of %u\n", nb_symbols_heuristic, window_size_tmp);
    for (uint32_t i = 0; i < nb_symbols_heuristic; ++i)
    {
        uint32_t source_esid = encoding_symbol_id - window_size_tmp + i + 1;
	    // TODO: wrap
        srv6_fec2_source_t *source = s.rlc_info.source_buffer[source_esid % SRV6_FEC_BUFFER_SIZE];
        if (!source || source->encoding_symbol_id != source_esid)
        {
            srv6_fec2_source_t *rec = s.rlc_info.recovd_buffer[source_esid % SRV6_FEC_BUFFER_SIZE];
            if (!rec || rec->encoding_symbol_id != source_esid)
            {
                // click_chatter("Heuristic gives that we should recover a symbol: %u\n", source_esid);
                useful_repair = true;
                break;
            }
        }
        stream_id = repair_tmp->tlv.stream_id;
    }
    if (!useful_repair)
    {
        return;
    }
    first_esi_last_rs = encoding_symbol_id - window_size_tmp;

    int nb_unk_tmp = 0;
    int nb_fdd_tmp = 0;
    for (int i = 0; i < MIN(nb_symbols_to_loop, window_size_tmp); ++i)
    {
        uint32_t esi = encoding_symbol_id - i;
        srv6_fec2_repair_t *repair = s.rlc_info.repair_buffer[esi % SRV6_FEC_BUFFER_SIZE];
        // Did not receive this repair symbol => stop iteration
        if (repair && repair->p && repair->tlv.rfpid == esi)
        {
            ++nb_fdd_tmp;
        }
        srv6_fec2_source_t *source = s.rlc_info.source_buffer[esi % SRV6_FEC_BUFFER_SIZE];
        if (!source || source->encoding_symbol_id != esi)	
	    {
	        srv6_fec2_source_t *rec = s.rlc_info.recovd_buffer[esi % SRV6_FEC_BUFFER_SIZE];
            if (!rec || rec->encoding_symbol_id != esi)
            {
                ++nb_unk_tmp;
            }
	    }
    }
    if (nb_unk_tmp > nb_fdd_tmp)
    {
        return;
    }

    // 1. Detect the size of the system:
    //      - Number of rows (i.e., equations or repair symbols)
    //      - Number of columns (i.e., unknowns or lost source symbols)
    uint16_t nb_windows = 0;                                 // One window = one repair symbol
    uint32_t running_esid = encoding_symbol_id;              // esid = encoding symbol id
    uint32_t first_esi_previous_rs = encoding_symbol_id + 1; // For first loop
    uint32_t rs_indicator[RLC_MAX_WINDOWS];

    // We can also not iterate over all the buffer and stop at s.esi_last_in_sequence;
    // Indeed, a repair symbol at s.esi_last_in_sequence means that we would try to recover data
    // that is before s.esi_last_in_sequence, which is not needed
    for (int i = 0; i < nb_symbols_to_loop; ++i)
    {
        srv6_fec2_repair_t *repair = s.rlc_info.repair_buffer[running_esid % SRV6_FEC_BUFFER_SIZE];
        // Did not receive this repair symbol => stop iteration
        if (!repair || !repair->p || repair->tlv.rfpid != running_esid)
        {
            --running_esid;
            continue; // No worries if we skip ine
        }
        if (running_esid < first_esi_previous_rs && nb_windows > 0)
        {
            break;
        }

        // The repair symbol contains out-of-window source symbols that it will consider as lost
        // BUT they are just out of window so we don't want them
        if (i + repair->tlv.nss >= SRV6_FEC_BUFFER_SIZE)
        {
            break;
        }

        

        const click_ip6_sr *srv6 = reinterpret_cast<const click_ip6_sr *>(repair->p->data() + sizeof(click_ip6));
        uint16_t repair_offset = sizeof(click_ip6) + sizeof(click_ip6_sr) + srv6->ip6_hdrlen * 8;
        max_packet_length = MAX(max_packet_length, repair->p->length() - repair_offset);
#if TRY_PREFETCH
        if (_prefetch) {
            rte_prefetch0(repair->p->data() + repair_offset);
        }
#endif
        assert(max_packet_length < 2048);

        window_size = repair->tlv.nss;

        // Constrain a bit the system
        if (nb_source_symbols + window_size > SRV6_RLC_MAX_SYMBOLS)
        {
            break; // Too much symbols otherwise
        }
        max_seen_window_size = MAX(max_seen_window_size, window_size);
        nb_source_symbols += window_size;
        if (running_esid > first_esi_previous_rs)
        {
            nb_source_symbols -= running_esid - first_esi_previous_rs;
        }
        first_esi_previous_rs = running_esid - window_size;

        rs_indicator[nb_windows++] = running_esid;
        // Break the loop after one of the two conditions:
        // - enough windows
        // - no repair symbols linked to the current window
        if (nb_windows >= RLC_MAX_WINDOWS)
        {
            break;
        }
        --running_esid;
    }

    // No valid window: no repair symbol received or no FEC applied
    // Should not happen since this function is triggered by the
    // reception of a repair symbol
    if (unlikely(nb_windows == 0))
    {
        click_chatter("Should not happen empty window");
        return;
    }

    // Received source symbols array
    srv6_fec2_source_t **ss_array = s.rlc_utils.ss_array;
    memset(ss_array, 0, sizeof(srv6_fec2_source_t *) * nb_source_symbols);

    // Received repair symbols array
    srv6_fec2_repair_t **rs_array = s.rlc_utils.rs_array;
    memset(rs_array, 0, sizeof(srv6_fec2_repair_t *) * nb_windows);

    uint16_t nb_unknwons = 0;
    uint16_t *x_to_source = s.rlc_utils.x_to_source;
    uint16_t *source_to_x = s.rlc_utils.source_to_x;
    memset(x_to_source, 0, sizeof(uint16_t) * nb_source_symbols);
    memset(source_to_x, -1, sizeof(uint16_t) * nb_source_symbols);

    bool *protected_symbol = s.rlc_utils.protected_symbols;
    memset(protected_symbol, 0, sizeof(bool) * nb_source_symbols);

    uint32_t id_first_ss_first_window = encoding_symbol_id - nb_source_symbols + 1;
    for (int i = 0; i < nb_windows; ++i)
    {
        srv6_fec2_repair_t *repair = s.rlc_info.repair_buffer[rs_indicator[i] % SRV6_FEC_BUFFER_SIZE];
        if (!repair)
        {
            click_chatter("ERROR 3");
            return; // TODO: free all
        }
        rs_array[i] = repair;
    }

    for (int i = nb_source_symbols - 1; i >= 0; --i)
    {
        int idx = (id_first_ss_first_window + i) % SRV6_FEC_BUFFER_SIZE;
        srv6_fec2_source_t *source = s.rlc_info.source_buffer[idx];
        uint32_t id_theoric = id_first_ss_first_window + i;
        bool is_lost = false;

        if (source && source->encoding_symbol_id == id_theoric)
        {
            // Received symbol, store it in the buffer
            ss_array[i] = source;
#if TRY_PREFETCH
                if (_prefetch) {
                    uint16_t repair_offset = sizeof(click_ip6) + sizeof(click_ip6_sr);
                    rte_prefetch0(source->p->data() + repair_offset);
                }
#endif
        }
        else
        {
            is_lost = 1;
        }
        if (is_lost) // Do not use recovered symbols anymore because maybe corrupted
        {                 // Maybe this symbol was recovered earlier and stored in recovered buffer
            srv6_fec2_source_t *rec = s.rlc_info.recovd_buffer[idx];
            if (rec && rec->encoding_symbol_id == id_theoric)
            {
                ss_array[i] = rec;
#if TRY_PREFETCH
                if (_prefetch) {
                    uint16_t repair_offset = sizeof(click_ip6) + sizeof(click_ip6_sr);
                    rte_prefetch0(rec->p->data() + repair_offset);
                }
#endif
                // Hence the packet is not lost anymore
                is_lost = 0;
            }
        }
        if (is_lost)
        {
            x_to_source[nb_unknwons] = i;
            source_to_x[i] = nb_unknwons;
            ++nb_unknwons;
        }

    }

    // Maybe no need for recovery
    if (nb_unknwons == 0)
    {
        click_chatter("No unknown");
        return;
    }

    // Construct the system Ax=b
    int n_eq = MIN(nb_unknwons, nb_windows);
    uint8_t *coefs = s.rlc_utils.coefs;
    srv6_fec2_term_t **unknowns = s.rlc_utils.unknowns;
    uint8_t **system_coefs = s.rlc_utils.system_coefs;
    srv6_fec2_term_t **constant_terms = s.rlc_utils.constant_terms;
    bool *undetermined = s.rlc_utils.undetermined;
    memset(coefs, 0, max_seen_window_size * sizeof(uint8_t));
    memset(unknowns, 0, sizeof(srv6_fec2_term_t *) * nb_unknwons);
    memset(constant_terms, 0, sizeof(srv6_fec2_term_t *) * nb_unknwons);
    memset(undetermined, 0, sizeof(bool) * nb_unknwons);
    for (int i = 0; i < n_eq; ++i)
    {
        memset(system_coefs[i], 0, sizeof(uint8_t) * nb_unknwons);
    }
    int i = 0; // Index of the row in the system
    int nb_repair_symbols_active = 0;
    int nb_lost_source_symbols_active = 0;
    uint64_t idx_most_recent_lost_detected = 1 << 18;
    for (int rs = 0; rs < nb_windows; ++rs)
    {
	    int nb_lost_source_this = 0;
        srv6_fec2_repair_t *repair = rs_array[rs];
        uint16_t this_window_size = repair->tlv.nss;
        uint32_t this_encoding_symbol_id = repair->tlv.rfpid;
        bool protect_at_least_one = false;
        // Check if this repair symbol protects at least one lost source symbol
        // the following seems correct
        int idx = this_encoding_symbol_id - id_first_ss_first_window - this_window_size + 1; // TODO: check if correct
        uint32_t idx_from_last = this_encoding_symbol_id - id_first_ss_first_window;         // - this_window_size + 1;
        for (int k = 0; k < this_window_size; ++k)
        {
            if (!ss_array[idx_from_last - k] && idx_most_recent_lost_detected > idx_from_last - k)
            {
                nb_lost_source_this++;
                idx_most_recent_lost_detected = idx_from_last - k;
            }
	    if (!ss_array[idx_from_last - k] && !protected_symbol[idx_from_last - k] && !protect_at_least_one)
            {
                protect_at_least_one = true;
                protected_symbol[idx_from_last - k] = true;
                // break; // We know it protects at least one
            }
        }
        if (!protect_at_least_one)
        {
            continue; // Ignore this repair symbol if does not protect any lost
        }
	    ++nb_repair_symbols_active;
	    nb_lost_source_symbols_active += nb_lost_source_this; // TODO: overlap !

        // 1) Independent term (b) ith row
        const click_ip6_sr *srv6 = reinterpret_cast<const click_ip6_sr *>(repair->p->data() + sizeof(click_ip6));
        uint16_t repair_offset = sizeof(click_ip6) + sizeof(click_ip6_sr) + srv6->ip6_hdrlen * 8;

        // 2) Coefficient matrix (A) ith row
        uint16_t repair_key = repair->tlv.rfi & 0xffff;
        int current_unknown = 0;                                                         // Nb of unknown already discovered
        idx = this_encoding_symbol_id - id_first_ss_first_window - this_window_size + 1; // TODO: check if correct
        for (int j = 0; j < this_window_size; ++j)
        {
            int idx_this_ss = idx + j; // Index of location of this source symbol
            if (ss_array[idx_this_ss] && !repair->decoded_ind[j])
            { // This protected symbol is received
                symbol_sub_scaled_term(repair, coefs[j], ss_array[idx_this_ss], _rlc_params.muls, repair_offset, s);
                repair->decoded_ind[j] = true;
            }
            else if (!ss_array[idx_this_ss])
            {
                if (source_to_x[idx_this_ss] != -1)
                {
                    system_coefs[i][source_to_x[idx_this_ss]] = coefs[j]; // A[i][j] = coefs[j]
                    ++current_unknown;
                }
                else
                {
                    click_chatter("ERROR 4");
                }
            } // Else: already decoded this source symbol in the repair symbol => win processing time
        }
        constant_terms[i] = init_term(repair->p, repair_offset, max_packet_length);
        constant_terms[i]->length.coded_length = repair->tlv.coded_length;
        ++i;

	if (_minimal_system_fec && nb_repair_symbols_active >= nb_lost_source_symbols_active)
	{
	    nb_unknwons = nb_lost_source_symbols_active;
	    break;
	}
    }
    uint16_t nb_effective_equations = i;

    total_system_tried++;
    bool can_recover = nb_effective_equations >= nb_unknwons;
    if (can_recover)
    {
        // Update the last received ESI in sequence as the ESI of the latest source symbol considered in the system
	    // TODO: if the last repair symbol is not considered, then we need to update this value
	    s.esi_last_in_sequence = last_esi; 
        // Solve the system
        gauss_elimination(nb_effective_equations, nb_unknwons, system_coefs, constant_terms, unknowns, undetermined, _rlc_params.muls, _rlc_params.table_inv, max_packet_length, s);
        // click_chatter("Recover some packets!");

        if (nb_unk_tmp > nb_fdd_tmp) 
            click_chatter("---------------RESOLVED BUT GUESSED %u > %u", nb_unk_tmp, nb_fdd_tmp);
	    uint16_t current_unknown = 0;
        int err = 0;
        total_system_done++;
        bool is_first_rec = true;

        for (int j = 0; j < nb_unknwons; ++j)
        {
            int idx = x_to_source[j];
            if (!ss_array[idx] && !undetermined[current_unknown])
            {
                // if (true) continue;
                // Avoid stupid errors
                if (unknowns[current_unknown]->length.data_length > max_packet_length)
                {
                    click_chatter("SID=%u Wrong size: %u %u for packet %u", stream_id, unknowns[current_unknown]->length.data_length, max_packet_length, id_first_ss_first_window + idx);
                    continue;
                }
                // if (unknowns[current_unknown]->length.data_length != 1074) {
                //     click_chatter("BAD LENGTH Len %d", unknowns[current_unknown]->length.data_length);
                //     continue;
                // }
                // Packet from the recovered data
                WritablePacket *p_rec = recover_packet_fom_data(unknowns[current_unknown], is_first_rec);
                if (unlikely(!p_rec))
                {
                /*    click_chatter("nb_effective=%u, nb_unk=%u, nb_windows=%u", nb_effective_equations, nb_unknwons, nb_windows);
                    click_chatter("Error from recovery confirmed for packet %u -> %u", id_first_ss_first_window, id_first_ss_first_window + idx);
                    for (int i = id_first_ss_first_window; i < id_first_ss_first_window + idx; i++) {
                        // ss_array[i]->encoding_symbol_id
                        click_chatter("%d -> %d, %p %p",
                        id_first_ss_first_window,
                        i,
                        s.rlc_info.source_buffer[i % SRV6_FEC_BUFFER_SIZE], 
                        s.rlc_info.recovd_buffer[i % SRV6_FEC_BUFFER_SIZE]);
                        if (s.rlc_info.source_buffer[i % SRV6_FEC_BUFFER_SIZE] && s.rlc_info.source_buffer[i % SRV6_FEC_BUFFER_SIZE]->p) {
                            click_chatter("Source %p / %d : %x", s.rlc_info.source_buffer[i % SRV6_FEC_BUFFER_SIZE]->p, s.rlc_info.source_buffer[i % SRV6_FEC_BUFFER_SIZE]->encoding_symbol_id, s.rlc_info.source_buffer[i % SRV6_FEC_BUFFER_SIZE]->p->data()[64]);
                        }
                        if (s.rlc_info.recovd_buffer[i % SRV6_FEC_BUFFER_SIZE] && s.rlc_info.recovd_buffer[i % SRV6_FEC_BUFFER_SIZE]->p) {
                            click_chatter("Source %p / %d : %x",s.rlc_info.recovd_buffer[i % SRV6_FEC_BUFFER_SIZE]->p, s.rlc_info.recovd_buffer[i % SRV6_FEC_BUFFER_SIZE]->encoding_symbol_id, s.rlc_info.recovd_buffer[i % SRV6_FEC_BUFFER_SIZE]->p->data()[64]);
                        }
                    }*/
                    //assert(false);
                    continue;
                };
                is_first_rec = false;

                // click_chatter("Recovered the packet with esid=%u (%x)", id_first_ss_first_window + idx, id_first_ss_first_window + idx);
                //  New pointer for the recovered values
                srv6_fec2_source_t *recovered;
                // Optimization: reuse the previous recovered symbol if present in the buffer
                srv6_fec2_source_t *old_rec = s.rlc_info.recovd_buffer[(id_first_ss_first_window + idx) % SRV6_FEC_BUFFER_SIZE];
                if (likely(old_rec))
                {
                    if (likely(old_rec->p))
                    {
                        old_rec->p->kill();
                        old_rec->p = 0;
                    }
                    recovered = old_rec;
                }
                else
                {
                    recovered = (srv6_fec2_source_t *)CLICK_LALLOC(sizeof(srv6_fec2_source_t));
                }

                recovered->encoding_symbol_id = id_first_ss_first_window + idx;

                // Store a local copy of the packet for later recovery?
#if HAVE_DPDK
                if (_clone) {
                    recovered->p = p_rec->clone(true);
                    assert(rte_mbuf_refcnt_read((rte_mbuf*)recovered->p->destructor_argument()) == 2);
                    recovered->p->set_buffer_destructor(DPDKDevice::free_pkt_empty);
                    p_rec->set_buffer_destructor(DPDKDevice::free_pkt_empty);
                } else
#endif       
		{
                    recovered->p = p_rec->clone();
                }
                
                recovered->initial_plen = recovered->p->length();
                memcpy(&recovered->dst, recovered->p->data(), sizeof(struct in6_addr));
                // memcpy((void *)recovered->p->data(), &recovered->dst, sizeof(struct in6_addr));
                //click_ip6 *ip6 = reinterpret_cast<click_ip6 *>(p_rec);
                //ip6->ip6_ctlun.ip6_un1.ip6_un1_hlim = 42; // To recognize them!
                // click_chatter("Recover a packet %u %x", p_rec->data()[7], p_rec->data()[7]);
                
                push(p_rec);
                // output(1).push_batch(PacketBatch::make_from_packet(p_rec));
                total_recovered++;
                s.rlc_info.recovd_buffer[recovered->encoding_symbol_id % SRV6_FEC_BUFFER_SIZE] = recovered;
            }
            else
            {
                total_bad_recovered++;
                if (total_system_done % 100 == 0 && 0)
                {
                    click_chatter("Cannot recover %u even if solvable system nbe=%u nbu=%u-------------------------------", id_first_ss_first_window + idx,  nb_effective_equations, nb_unknwons);
                    click_chatter("nb effective eq=%u, nb_unk=%u", nb_effective_equations, nb_unknwons);
                    click_chatter("Les repair symbols utilises");
                    for (int i = 0; i < nb_windows; ++i)
                    {
                        printf("%u ", rs_indicator[i]);
                    }
                    printf("\n");
                    printf("Les idx perdus sont (%u): ", nb_unknwons);
                    for (int i = 0; i < nb_unknwons; ++i)
                    {
                        printf("%u ", id_first_ss_first_window + x_to_source[i]);
                    }
                    printf("\n");
                    printf("Du coup les RS utilises sont: ");
                    for (int i = 0; i < nb_effective_equations; ++i)
                    {
                        printf("%u ", rs_indicator[i]);
                    }
                    printf("\n");
                    click_chatter("Id first ss first symbol=%u", id_first_ss_first_window);
                    for (int k = 0; k < nb_effective_equations; ++k)
                    {
                        for (int l = 0; l < nb_unknwons; ++l)
                        {
                            printf("B[%u][%u]=%u ", k, l, system_coefs[k][l]);
                        }
                    }
                    printf("\n");
                }
            }
            ++current_unknown;
        }
    }
    else
    {
        s.rlc_info.nb_unknowns_last_system = nb_unknwons;
        s.rlc_info.nb_equations_last_system = nb_effective_equations;
        // click_chatter("Could not recover: %d %d\n", nb_unknwons, nb_effective_equations);
        /*if (nb_unknwons < 5 || nb_unk_tmp == 0)
        {
            click_chatter("\nNew system not solvable... ESI=%u, the 'last ok' ESI=%u so the iteration length was %u", encoding_symbol_id, s.esi_last_in_sequence, nb_symbols_to_loop);
            click_chatter("Eh ouais... %u %u, et l'heuristique: %u", nb_unk_tmp, nb_fdd_tmp, nb_symbols_heuristic);
            click_chatter("nb effective eq=%u, nb_unk=%u", nb_effective_equations, nb_unknwons);
            click_chatter("Les repair symbols utilises");
            for (int i = 0; i < nb_windows; ++i)
            {
                printf("%u ", rs_indicator[i]);
            }
            printf("\n");
            printf("Les idx perdus sont (%u): ", nb_unknwons);
            for (int i = 0; i < nb_unknwons; ++i)
            {
                printf("%u ", id_first_ss_first_window + x_to_source[i]);
            }
            printf("\n");
            printf("Du coup les RS utilises sont: ");
            for (int i = 0; i < nb_effective_equations; ++i)
            {
                printf("%u ", rs_indicator[i]);
            }
            printf("\n");
        }*/
    }

    // Free memory for the terms
    for (int j = 0; j < i; ++j)
    {
        if (constant_terms[j])
        {
            CLICK_LFREE(constant_terms[j]->data, max_packet_length);
            CLICK_LFREE(constant_terms[j], sizeof(srv6_fec2_term_t *));
        }
    }

    return;
}

void IP6SRv6FECDecode::symbol_add_scaled_term(srv6_fec2_repair_t *symbol1, uint8_t coef, srv6_fec2_source_t *symbol2, uint8_t *mul, uint16_t repair_offset, StreamState &s)
{
    // If the transport header offset is not 0, we assume that the packet changed
    // TODO: improve the generalization of this, using click_ip6->hdrlen
    // uint16_t offset = symbol2->p->network_header_offset();

    // The previous did not work because I don't know
    // Now only trying to do something working, doesn't care about the beauty of it
    uint16_t offset = 0;
    // Check manually if the packet got modified
    // If so, manually set an offset
    if (symbol2->p->data()[64] != 0xfc)
    {
        offset = 64;
    }
    if (offset == 0)
    {
        // The symbol did not change, so we perform the decoding on the whole packet
        symbol_add_scaled(symbol1->p->data() + repair_offset, coef, symbol2->p->data(), symbol2->p->length(), mul);
    }
    else
    {
        assert(offset < symbol2->p->length());
        uint16_t current_length = symbol2->p->length();

        // Copy the current destination of the packet as the last segment of the SRH segment list
        const click_ip6 *ip6 = reinterpret_cast<const click_ip6 *>(symbol2->p->data());
        memcpy(&s.white_srv6->segments[0], &ip6->ip6_dst, sizeof(IP6Address));
        uint8_t *dd = (uint8_t *)&s.white_srv6->segments[1];
        s.white_srv6->ip6_sr_next = symbol2->srv6_next_hdr;
        // The packet changed. We must decode in 3 steps:
        // 1. Decode the IPv6 Header
        symbol_add_scaled(symbol1->p->data() + repair_offset, coef, symbol2->p->data() + offset, sizeof(click_ip6), mul);
        // 2. White noise decode the SRv6
        symbol_add_scaled(symbol1->p->data() + repair_offset + sizeof(click_ip6), coef, s.white_srv6, 64, mul);
        // 3. Decode the IPv6 payload
        symbol_add_scaled(symbol1->p->data() + repair_offset + sizeof(click_ip6) + s.white_srv6_total_length, coef, symbol2->p->data() + offset + sizeof(click_ip6), current_length - sizeof(click_ip6) - s.white_srv6_total_length, mul);
    }

    uint16_t pl = (uint16_t)symbol2->initial_plen;
    symbol_add_scaled(&symbol1->tlv.coded_length, coef, &pl, sizeof(uint16_t), mul);
}

void IP6SRv6FECDecode::symbol_add_scaled_term(srv6_fec2_term_t *symbol1, uint8_t coef, srv6_fec2_term_t *symbol2, uint8_t *mul, uint16_t decoding_size, StreamState &s)
{
    symbol_add_scaled(symbol1->data, coef, symbol2->data, decoding_size, mul);
    uint16_t pl = (uint16_t)symbol2->length.coded_length;
    symbol_add_scaled(&symbol1->length.coded_length, coef, &pl, sizeof(uint16_t), mul);
}

void IP6SRv6FECDecode::symbol_mul_term(srv6_fec2_term_t *symbol1, uint8_t coef, uint8_t *mul, uint16_t size)
{
    symbol_mul(symbol1->data, coef, size, mul);
    symbol_mul((uint8_t *)&symbol1->length.coded_length, coef, sizeof(uint16_t), mul);
}

void IP6SRv6FECDecode::swap(uint8_t **a, int i, int j)
{
    uint8_t *tmp = a[j];
    a[j] = a[i];
    a[i] = tmp;
}

void IP6SRv6FECDecode::swap_b(srv6_fec2_term_t **a, int i, int j)
{
    srv6_fec2_term_t *tmp = a[j];
    a[j] = a[i];
    a[i] = tmp;
}

int IP6SRv6FECDecode::cmp_eq_i(uint8_t *a, uint8_t *b, int idx, int n_unknowns)
{
    if (a[idx] < b[idx])
        return -1;
    else if (a[idx] > b[idx])
        return 1;
    else if (a[idx] != 0)
        return 0;
    return 0;
}

int IP6SRv6FECDecode::cmp_eq(uint8_t *a, uint8_t *b, int idx, int n_unknowns)
{
    for (int i = 0; i < n_unknowns; i++)
    {
        int cmp = 0;
        if ((cmp = cmp_eq_i(a, b, i, n_unknowns)) != 0)
        {
            return cmp;
        }
    }
    return 0;
}

void IP6SRv6FECDecode::sort_system(uint8_t **a, srv6_fec2_term_t **constant_terms, int n_eq, int n_unknowns)
{
    for (int i = 0; i < n_eq; ++i)
    {
        int max = i;
        for (int j = i + 1; j < n_eq; ++j)
        {
            if (cmp_eq(a[max], a[j], i, n_unknowns) < 0)
            {
                max = j;
            }
        }
        swap(a, i, max);
        swap_b(constant_terms, i, max);
    }
}

int IP6SRv6FECDecode::first_non_zero_idx(const uint8_t *a, int n_unknowns)
{
    for (int i = 0; i < n_unknowns; i++)
    {
        if (a[i] != 0)
        {
            return i;
        }
    }
    return -1;
}

void IP6SRv6FECDecode::gauss_elimination(int n_eq, int n_unknowns, uint8_t **a, srv6_fec2_term_t **constant_terms, srv6_fec2_term_t **x, bool *undetermined, uint8_t *mul, uint8_t *inv, uint16_t max_packet_length, StreamState &s)
{
    sort_system(a, constant_terms, n_eq, n_unknowns);
    for (int i = 0; i < n_eq - 1; ++i)
    {
        for (int k = i + 1; k < n_eq; ++k)
        {
            uint8_t mul_num = a[k][i];
            uint8_t mul_den = a[i][i];
            uint8_t term = gf256_mul(mul_num, inv[mul_den], mul);
            for (int j = 0; j < n_unknowns; ++j)
            {
                a[k][j] = gf256_sub(a[k][j], gf256_mul(term, a[i][j], mul));
            }
            symbol_sub_scaled_term(constant_terms[k], term, constant_terms[i], mul, max_packet_length, s);
        }
    }

    sort_system(a, constant_terms, n_eq, n_unknowns);

    for (int i = 0; i < n_eq - 1; ++i)
    {
        int first_nz_id = first_non_zero_idx(a[i], n_unknowns);
        if (first_nz_id == -1)
        {
            break;
        }
        for (int j = first_nz_id + 1; j < n_unknowns && a[i][j] != 0; j++)
        {
            for (int k = i + 1; k < n_eq; k++)
            {
                int first_nz_id_below = first_non_zero_idx(a[k], n_unknowns);
                if (j > first_nz_id_below)
                {
                    break;
                }
                else if (first_nz_id_below == j)
                {
                    uint8_t term = gf256_mul(a[i][j], inv[a[k][j]], mul);
                    for (int l = j; l < n_unknowns; l++)
                    {
                        a[i][l] = gf256_sub(a[i][l], gf256_mul(term, a[k][l], mul));
                    }
                    symbol_sub_scaled_term(constant_terms[i], term, constant_terms[k], mul, max_packet_length, s);
                    break;
                }
            }
        }
    }

    int candidate = n_unknowns - 1;
    for (int i = n_eq - 1; i >= 0; --i)
    {
        bool only_zeroes = true;
        for (int j = 0; j < n_unknowns; ++j)
        {
            if (a[i][j] != 0)
            {
                only_zeroes = false;
                break;
            }
        }
        if (!only_zeroes)
        {
            while (a[i][candidate] == 0 && candidate >= 0)
            {
                // click_chatter("W5");
                undetermined[candidate--] = true;
            }
            if (candidate < 0)
            {
                break;
            }
            // TODO: not optimal because of aliasing
            x[candidate] = constant_terms[i]; // Simply pointer copy
            for (int j = 0; j < candidate; ++j)
            {
                if (a[i][j] != 0)
                {
                    // click_chatter("W2");
                    undetermined[candidate] = true;
                    break;
                }
            }
            for (int j = candidate + 1; j < n_unknowns; ++j)
            {
                if (a[i][j] != 0)
                {
                    if (undetermined[j])
                    {
                        // click_chatter("W0");
                        undetermined[candidate] = true;
                    }
                    else
                    {
                        symbol_sub_scaled_term(x[candidate], a[i][j], x[j], mul, max_packet_length, s);
                        a[i][j] = 0;
                    }
                }
            }
            if (symbol_is_zero(x[candidate]->data, x[candidate]->length.data_length) || a[i][candidate] == 0)
            {
                // click_chatter("W1");
                undetermined[candidate] = true;
            }
            else if (!undetermined[candidate])
            {
                symbol_mul_term(x[candidate], inv[a[i][candidate]], mul, max_packet_length);
                a[i][candidate] = gf256_mul(a[i][candidate], inv[a[i][candidate]], mul);
            }
            candidate--;
        }
    }
    if (candidate >= 0)
    {
        // click_chatter("W3");
        memset(undetermined, true, (candidate + 1) * sizeof(bool));
    }
}

void IP6SRv6FECDecode::gauss_elimination2(int n_eq, int n_unknowns, uint8_t **a, srv6_fec2_term_t **constant_terms, srv6_fec2_term_t **x, bool *undetermined, uint8_t *mul, uint8_t *inv, uint16_t max_packet_length, StreamState &s)
{
    for (int i = 0; i < n_eq - 1; ++i)
    {
        for (int k = i + 1; k < n_eq; ++k)
        {
            uint8_t mul_num = a[k][i];
            uint8_t mul_den = a[i][i];
            uint8_t term = gf256_mul(mul_num, inv[mul_den], mul);
            for (int j = 0; j < n_unknowns; ++j)
            {
                a[k][j] = gf256_sub(a[k][j], gf256_mul(term, a[i][j], mul));
            }
            symbol_sub_scaled_term(constant_terms[k], term, constant_terms[i], mul, max_packet_length, s);
        }
    }
    uint8_t *factor_tab = (uint8_t *)malloc(sizeof(uint8_t) * max_packet_length);
    uint16_t length = 0;
    for (int i = n_unknowns - 1; i >= 0; --i)
    {
        memset(factor_tab, 0, sizeof(uint8_t) * max_packet_length);
        for (int j = i + 1; j < n_unknowns; --j)
        {
            symbol_add_scaled(factor_tab, a[i][j], constant_terms[j]->data, max_packet_length, mul);
            symbol_add_scaled(&length, a[i][j], &constant_terms[j]->length.coded_length, sizeof(uint16_t), mul);
            // symbol_sub_scaled_term(factor_tab, a[i][j], constant_terms[j], mul, max_packet_length, s);
        }
        for (int k = 0; k < max_packet_length; ++k)
        {
            constant_terms[i]->data[k] ^= factor_tab[k];
            constant_terms[i]->length.coded_length ^= length;
            constant_terms[i]->data[k] = gf256_mul(constant_terms[i]->data[k], inv[a[i][i]], mul);
            constant_terms[i]->length.coded_length = gf256_mul(constant_terms[i]->length.coded_length, inv[a[i][i]], mul);
        }
        x[i] = constant_terms[i];
    }
    memset(undetermined, false, sizeof(bool) * n_unknowns);
}

uint16_t
IP6SRv6FECDecode::get_offset_in_source(srv6_fec2_source_t *source)
{
    uint16_t current_length = source->p->length();
    if (current_length != source->initial_plen)
    {
        click_chatter("Previous was: %u current is %u", source->initial_plen, current_length);
        // Compute offset of the new IPv6 Header
        return source->initial_plen - current_length; // TODO: check if correct
    }
    else
    {
        // The packet did not change
        return 0;
    }
}

WritablePacket *
IP6SRv6FECDecode::recover_packet_fom_data(srv6_fec2_term_t *rec, bool is_first_rec)
{
    // Create new packet for the recovered data
    WritablePacket *p = Packet::make(rec->length.data_length);

    // Copy the data from the buffer inside the new packet
    // TODO: optimization: direclty un a Packet ?
    memcpy(p->data(), rec->data, rec->length.data_length);

    // Recover from varying fields
    click_ip6 *ip6 = reinterpret_cast<click_ip6 *>(p->data());
    click_ip6_sr *srv6 = reinterpret_cast<click_ip6_sr *>(p->data() + sizeof(click_ip6));
    // 1. Detect the correct new next hop
    uint32_t *dec_ip_32 = dec.data32();
    bool found_next_sid = false;
    struct in6_addr ip6_next;
    int i = srv6->last_entry;
    int len;
    uint16_t offset;
    // click_chatter("SRV6: %u %u %u %u %u", srv6->ip6_sr_next, srv6->ip6_hdrlen, srv6->type, srv6->segment_left, srv6->last_entry);
    uint8_t *dec_8 = (uint8_t *)dec_ip_32;
    while (i >= 0)
    {
        uint16_t offset = sizeof(click_ip6_sr) + sizeof(struct in6_addr) * i;
        memcpy(&ip6_next, ((uint8_t *)srv6) + offset, sizeof(struct in6_addr));
        // Compare this SID with the decoder ID
        uint32_t *in6_32 = (uint32_t *)ip6_next.s6_addr;
        uint8_t *en_8 = (uint8_t *)&ip6_next;
        // click_chatter("IPv6 segment: %x %x %x %x", en_8[0], en_8[1], en_8[2], en_8[3]);
        if (dec_ip_32[0] == in6_32[0] && dec_ip_32[1] == in6_32[1] && dec_ip_32[2] == in6_32[2] && dec_ip_32[3] == in6_32[3])
        {
            found_next_sid = true;
            //            click_chatter("I HAVE FOUND THE SID");
            break;
        }
        --i;
    }
    if (unlikely(!found_next_sid || i == 0))
    {
        //click_chatter("Did not find the SID => error");
        goto bad;
    }

    // Next Header of the IPv6 Header could have been another value because of the clone() so we reset it
    ip6->ip6_nxt = IP6_EH_ROUTING;
    --i; // Next segment is the next hop
    offset = sizeof(click_ip6_sr) + sizeof(struct in6_addr) * i;

    // 2. Replace the destination address with the correct
    memcpy(&ip6->ip6_dst, ((uint8_t *)srv6) + offset, sizeof(struct in6_addr));

    // 3. Replace the Segment Left pointer
    srv6->segment_left = i;

    // 4. New hop limit
    ip6->ip6_hlim = 52;
    
    // ip6->ip6_vfc &= 0b11111100;

    // 5. Set possible ECN bits.
    // ip6->ip6_flow &= ~((0b01) << 12);
    if (is_first_rec && _use_ecn && rec->length.data_length > 160) {
        ip6->ip6_flow |= (0b11) << 12;
        // click_chatter("Set ECN to true");
    }

    // 6. Compute the checksum
    // TODO : utiliser un element si besoin

    // 6. Set the payload length (because wrongly recovered)
    ip6->ip6_plen = htons(rec->length.data_length - sizeof(click_ip6));

    // 6. Copy the destination address in the last (i.e. upper) segment for decap
    // memcpy(&srv6->segments[0], &ip6->ip6_dst, sizeof(struct in6_addr));
    memcpy(&ip6->ip6_dst, &srv6->segments[0], sizeof(struct in6_addr));

    // 7. Set annotations
    len = sizeof(click_ip6) + sizeof(click_ip6_sr) + sizeof(struct in6_addr) * srv6->last_entry + 8;
    if (unlikely(len > rec->length.data_length)) {
        click_chatter("Invalid recovered packet length");
        goto bad;
    } else {
        p->set_network_header((unsigned char *)ip6, len);
    }

    return p;
    bad:
    p->kill();
    return 0;
}

void IP6SRv6FECDecode::xor_recover_symbols(std::function<void(Packet *)> push, StreamState &s)
{
    uint32_t esid = s.rlc_info.encoding_symbol_id;
    srv6_fec2_repair_t *repair = s.rlc_info.repair_buffer[esid % SRV6_FEC_BUFFER_SIZE];
    uint16_t window_size = repair->tlv.nss;
    const click_ip6_sr *srv6 = reinterpret_cast<const click_ip6_sr *>(repair->p->data() + sizeof(click_ip6));
    uint16_t repair_offset = sizeof(click_ip6) + sizeof(click_ip6_sr) + srv6->ip6_hdrlen * 8;
    uint16_t max_packet_length = repair->p->length() - repair_offset;

    assert(max_packet_length < 2048);

    // 1. Detect if we can recover a lost source symbol in the window
    //    If there are more than one lost symbol in the window, we cannot recover it
    //    Store them in a separate buffer for easier access
    Packet *xor_buff[window_size];
    uint16_t nb_source = 0;
    bool lost_one_symbol = false;
    uint32_t lost_esid = 0;
    for (uint32_t i = 0; i < window_size; ++i)
    {
        // Iterate from the end but XOR is commutative and associative
        uint16_t idx = (esid - i) % SRV6_FEC_BUFFER_SIZE;
        uint32_t theoric_esid = esid - i;
        srv6_fec2_source_t *source = s.rlc_info.source_buffer[idx];
        srv6_fec2_source_t *rec = s.rlc_info.recovd_buffer[idx];
        if (source && source->encoding_symbol_id == theoric_esid)
        {
            xor_buff[nb_source++] = source->p;
        }
        else if (rec && rec->encoding_symbol_id == theoric_esid)
        {
            // Maybe the symbol was recovered earlier in a previous window
            xor_buff[nb_source++] = rec->p;
        }
        else
        {
            if (lost_one_symbol)
            {
                return; // More than one lost symbol, cannot recover
            }
            lost_one_symbol = true;
            lost_esid = theoric_esid;
        }
    }

    if (!lost_one_symbol)
    {
        return;
    }

    // 2. We know we have lost exactly one source symbol
    //    We can recover it by XORing the repair and source symbols
    srv6_fec2_term_t *rec = (srv6_fec2_term_t *)CLICK_LALLOC(sizeof(srv6_fec2_term_t));
    uint8_t *data = (uint8_t *)CLICK_LALLOC(sizeof(uint8_t) * max_packet_length);
    rec->length.coded_length = repair->tlv.coded_length;
    rec->data = data;
    // Copy data from the repair symbol
    memcpy(data, repair->p->data() + repair_offset, max_packet_length);
    for (uint32_t i = 0; i < nb_source; ++i)
    {
        xor_one_symbol(rec, xor_buff[i]);
    }

    // 3. Send the recovered symbol and store it in the recovered buffer
    //    Also make room if there was a previous recovered buffer
    WritablePacket *p_rec = recover_packet_fom_data(rec, true);
    if (unlikely(!p_rec))
    {
        click_chatter("Error confirmed");
    }
    else
    {
        srv6_fec2_source_t *prev_rec = s.rlc_info.recovd_buffer[lost_esid % SRV6_FEC_BUFFER_SIZE];
        if (prev_rec)
        {
            prev_rec->encoding_symbol_id = lost_esid;
            prev_rec->p = p_rec->clone();
        }
        else
        {
            srv6_fec2_source_t *rec = (srv6_fec2_source_t *)CLICK_LALLOC(sizeof(srv6_fec2_source_t));
            rec->encoding_symbol_id = lost_esid;
            rec->p = p_rec->clone();
            s.rlc_info.recovd_buffer[lost_esid % SRV6_FEC_BUFFER_SIZE] = rec;
        }

        push(p_rec);
    }

    CLICK_LFREE(data, sizeof(uint8_t) * max_packet_length);
    CLICK_LFREE(rec, sizeof(srv6_fec2_term_t));
}

void IP6SRv6FECDecode::xor_one_symbol(srv6_fec2_term_t *rec, Packet *s)
{
    uint8_t *s_64 = (uint8_t *)s->data();
    uint8_t *r_64 = (uint8_t *)rec->data;

    for (uint16_t i = 0; i < s->length() / sizeof(uint8_t); ++i)
    {
        // click_chatter("XOR with source i=%u  %x, repair before=%x", i, s_64[i], r_64[i]);
        r_64[i] ^= s_64[i];
    }

    // Also code the potential remaining data
    uint8_t *s_8 = (uint8_t *)s->data();
    uint8_t *r_8 = (uint8_t *)rec->data;
    for (uint16_t i = (s->length() / sizeof(uint8_t)) * sizeof(uint8_t); i < s->length(); ++i)
    {
        r_8[i] ^= s_8[i];
    }

    // Encode the packet length
    rec->length.coded_length ^= s->length();
}

void IP6SRv6FECDecode::compute_feedback_trace(StreamState &s, feedback_tlv_t *feedback)
{
    uint32_t window_size = s.last_window;
    int nb_windows = FEEDBACK_TIMELAG / window_size;
    bool *trace = s.rlc_feedback.packet_trace;

    uint64_t nb_active_windows = 0; // Number of windows containing at least a loss
    uint64_t sum_of_square = 0; // Sum of squares of the number of losses over each window.
    uint64_t current_sum = 0; // Total number of losses over the current window.
    uint64_t sum = 0; // Total number of losses over all windows.

    for (int i = 0; i < nb_windows; ++i) {
        current_sum = 0;

        for (int j = 0; j < window_size; ++j) {
            uint32_t esi = s.rlc_feedback.esid_last_feedback + i * window_size + j;
            if (!trace[esi % FEEDBACK_BUFFER_LENGTH]) {
                // This packet was lost.
                current_sum++;
            }
        }

        sum += current_sum;
        sum_of_square += current_sum * current_sum;

        // There is at least a loss in the window, so it is active.
        if (current_sum > 0) {
            nb_active_windows++;
        }
    }

    feedback->used_window_size = (uint16_t)window_size;
    // click_chatter("Used window size: %u\n", window_size);
    // click_chatter("Saw %u losses in %u active windows", feedback->total_losses = sum, feedback->nb_active_windows = nb_active_windows);
    feedback->nb_active_windows = nb_active_windows;
    feedback->total_losses = sum;
    feedback->total_losses_squared = sum_of_square;
}

void IP6SRv6FECDecode::rlc_feedback(StreamState &s, int stream_id)
{
    uint16_t packet_size = sizeof(click_ip6) + sizeof(click_ip6_sr) + 2 * sizeof(IP6Address) + sizeof(feedback_tlv_t);
    WritablePacket *p = Packet::make(packet_size);
    if (!p)
    {
        return;
    }

    click_ip6 *ip6 = reinterpret_cast<click_ip6 *>(p->data());
    click_ip6_sr *srv6 = reinterpret_cast<click_ip6_sr *>(p->data() + sizeof(click_ip6));
    feedback_tlv_t *tlv = reinterpret_cast<feedback_tlv_t *>(p->data() + sizeof(click_ip6) + sizeof(click_ip6_sr) + sizeof(IP6Address) * 2);

    // IPv6 Header
    memcpy(&ip6->ip6_src, dec.data(), sizeof(IP6Address));
    memcpy(&ip6->ip6_dst, feedback.data(), sizeof(IP6Address));
    ip6->ip6_flow = htonl(6 << IP6_V_SHIFT);
    ip6->ip6_plen = htons(packet_size - sizeof(click_ip6));
    ip6->ip6_nxt = IPPROTO_ROUTING;
    ip6->ip6_hlim = 56;

    // SRv6 Header
    srv6->type = IP6PROTO_SEGMENT_ROUTING;
    srv6->segment_left = 1;
    srv6->last_entry = 1;
    srv6->flags = 0;
    srv6->tag = 0;
    srv6->ip6_sr_next = 253;
    srv6->ip6_hdrlen = (sizeof(feedback_tlv_t) + 2 * sizeof(IP6Address)) / 8;
    memcpy(&srv6->segments[0], feedback.data(), sizeof(IP6Address));
    memcpy(&srv6->segments[1], feedback.data(), sizeof(IP6Address));

    // Add feedback TLV
    tlv->type = TLV_TYPE_FEC_FEEDBACK;
    tlv->len = sizeof(feedback_tlv_t) - 2;
    compute_feedback_trace(s, tlv);

    // Set annotations
    p->set_network_header(p->data(), (unsigned char *)(tlv + 1) - p->data());

    // Send packet with feedback
    // In batch mode this will FAIL
#if HAVE_BATCH
    output(1).push_batch(PacketBatch::make_from_packet(p));
#else
    output(1).push(p);
#endif

    // Reset parameters for next feedback
    s.rlc_feedback.esid_last_feedback = s.rlc_feedback.most_recent_esi;
    s.rlc_feedback.nb_received = 0;
    s.rlc_feedback.received_string = 0;
    memset(s.rlc_feedback.packet_trace, false, sizeof(bool) * FEEDBACK_BUFFER_LENGTH);
}

#define SYMBOL_FAST 1

#define ALIGNMENT 32
static __attribute__((always_inline)) size_t align(size_t val)
{
    return (val + ALIGNMENT - 1) / ALIGNMENT * ALIGNMENT;
}

static __attribute__((always_inline)) size_t align_below(size_t val)
{
    size_t retval = align(val);
    click_chatter("RETVAL: %d from %d\n", retval, val);
    if (retval > 0 && retval != val)
    {
        retval -= ALIGNMENT;
        click_chatter("After change: %d\n", retval);
    }
    return retval;
}

void IP6SRv6FECDecode::symbol_add_scaled_safe(void *symbol1, uint8_t coef, const void *symbol2, uint32_t symbol_size, uint8_t *mul)
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
void IP6SRv6FECDecode::symbol_add_scaled(void *symbol1, uint8_t coef, const void *symbol2, uint32_t symbol_size, uint8_t *mul)
{
    // Hidden.
}

bool IP6SRv6FECDecode::symbol_is_zero(void *symbol, uint32_t symbol_size)
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

void IP6SRv6FECDecode::symbol_mul(uint8_t *symbol1, uint8_t coef, uint32_t symbol_size, uint8_t *mul)
{
    // Hidden.
}

void IP6SRv6FECDecode::assign_inv(uint8_t *array)
{
    // Hidden.
}

void IP6SRv6FECDecode::click_gf256_init()
{
#if SYMBOL_USE_FAST_LIBRARY
    moepgf_init(&gflib_dec, MOEPGF256, MOEPGF_ALGORITHM_BEST);
#endif
}

CLICK_ENDDECLS
EXPORT_ELEMENT(IP6SRv6FECDecode)
ELEMENT_MT_SAFE(IP6SRv6FECDecode)
#if SYMBOL_USE_FAST_LIBRARY
ELEMENT_LIBS(-lmoepgf)
#endif
