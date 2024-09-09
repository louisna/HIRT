#ifndef CLICK_IP6SRv6FECEncode_HH
#define CLICK_IP6SRv6FECEncode_HH
#include <click/batchelement.hh>
#include <click/glue.hh>
#include <click/atomic.hh>
#include <clicknet/ip6.h>
#include <click/ip6address.hh>
#include <click/batchbuilder.hh>
#include <tinymt32/tinymt32.h>

#define SRV6_FEC_BUFFER_SIZE_ENC 1500

#ifndef SRV6FEC_HH
#define SRV6FEC_HH

#define TLV_TYPE_FEC_SOURCE 28
#define TLV_TYPE_FEC_REPAIR 29
#define LOCAL_MTU 1500

#ifndef NOSYMBOL_USE_FAST_LIBRARY
#define SYMBOL_USE_FAST_LIBRARY 1
#endif
#ifndef SYMBOL_USE_FAST_LIBRARY
#define SYMBOL_USE_FAST_LIBRARY 0
#endif

#define symbol_sub_scaled symbol_add_scaled
#define gf256_add(a, b) (a ^ b)
#define gf256_sub gf256_add
#define GRANULARITY 1000

// SRv6-FEC TLV structures
struct source_tlv_t
{
  uint8_t type;
  uint8_t len;
  uint8_t padding;
  uint8_t stream_id;
  uint32_t sfpid; // Source FEC Payload ID
} CLICK_SIZE_PACKED_ATTRIBUTE;

struct repair_tlv_t
{
  uint8_t type;
  uint8_t len;
  uint8_t padding;
  uint8_t stream_id;
  uint32_t rfpid; // Repair FEC Payload ID
  union
  {
    struct
    {
      uint8_t previous_window_size;
      uint8_t window_step;
      uint16_t repair_key;
    } rlc_rfi;
    uint32_t rfi;
  }; // Repair FEC Info
  uint16_t coded_length;
  uint16_t nss; // Number Source Symbol
} CLICK_SIZE_PACKED_ATTRIBUTE;

struct feedback_tlv_t
{
  uint8_t type;
  uint8_t len;
  //uint16_t nb_theoric;
  //uint16_t nb_lost;
  uint16_t stream_id;
  uint16_t used_window_size;
  uint16_t nb_active_windows;
  uint32_t total_losses;
  uint32_t total_losses_squared;
  //uint32_t last_received_esi;
  //uint16_t loss_burst_mean;
  //uint16_t loss_burst_std_dev;
} CLICK_SIZE_PACKED_ATTRIBUTE;

#endif

CLICK_DECLS

/*
=c

IP6SRv6FECEncode(ENC, DEC)

=s ip

Forward Erasure Correction for IPv6 Segment Routing

=d

Takes the encoder and decoder SIDs

=e


  IP6SRv6FECEncode(fc00::a, fc00::9)

=a IP6Encap */

struct rlc_param_t
{
  uint16_t _window_size; // Should no longer be used
  uint8_t _window_step; // Should no longer be used
  uint8_t muls[256 * 256 * sizeof(uint8_t)];
};

struct rlc_info_t
{
  uint32_t encoding_symbol_id;
  uint16_t repair_key;
  uint16_t buffer_size;
  uint16_t previous_window_step;
  bool generate_repair_symbols;
  double loss_estimation;
  double loss_burst_mean;
  double loss_burst_std_dev;
  uint64_t nb_feedback_received;
  double unbiased_loss_variance;
  double current_loss_mean;
  uint32_t added_repair;
  uint32_t esi_last_feedback;
  uint32_t last_sent_repair_esi;
  double threshold_loss;
  uint32_t esi_last_as_reset;
  double loss_mean_per_window;
  double loss_std_per_window;
  uint16_t window_size; // Current window size
  uint16_t min_step;
  uint32_t esi_last_full_window;       // ESI of the last time we had a full window (for burst losses)
  uint32_t nb_repair_sent_full_window; // Number of repair packets sent at this end of this full window
  bool is_sending_burst_repair;

  // With the new method.

  // RLC relative information
  tinymt32_t prng;
  uint16_t max_length;                             // Seen for this window
  Packet *source_buffer[SRV6_FEC_BUFFER_SIZE_ENC]; // Ring buffer
};

#define SRV6_FEC_RLC 0
#define SRV6_FEC_XOR 1
#define SRV6_FEC_FEEDBACK_INPUT 1

class IP6SRv6FECEncode : public BatchElement, public Router::InitFuture
{

public:
  IP6SRv6FECEncode();
  ~IP6SRv6FECEncode();

  const char *class_name() const override { return "IP6SRv6FECEncode"; }
  const char *port_count() const override { return "1-2/1"; } // Two inputs for the feedback

  int configure(Vector<String> &, ErrorHandler *) CLICK_COLD;
  bool can_live_reconfigure() const { return true; }
  void add_handlers() CLICK_COLD;

  void run_timer(Timer*);

  void push(int input, Packet *p_in) override;
#if HAVE_BATCH
  void push_batch(int input, PacketBatch *batch_in) override;
#endif

  static void static_initialize();
  int solve_initialize(ErrorHandler *errh) override;

private:
  struct State
  {
  
    source_tlv_t source_tlv;
    repair_tlv_t repair_tlv;
    rlc_info_t rlc_info;
    WritablePacket *repair_packet;
    click_ip6 repair_ip6;
    click_ip6_sr repair_srv6;
    PacketList builder;
    Timer* timer;

    inline int get_stream_id()
    {
      return _id + 32;
    }
    inline void set_thread_id(int id)
    {
      _id = id;
    }
    static int stream_id_to_threadid(int sid)
    {
      return sid - 32;
    }

  private:
    int _id; // Thread id (starts at 0)
  };
  atomic_uint64_t total_rs;
  per_thread<State> _state;
  uint8_t _fec_scheme;
  Timestamp _delay;
  bool _send_repair;
  uint16_t _max_window_size;
  bool _fast_fec;
  bool _extended_stats;
  rlc_param_t _rlc_params;
  double _alpha;
  double _beta;
  int _window_step;
  IP6Address enc; // Encoder SID
  IP6Address dec; // Decoder SID
  IP6Address fed; // Feedback SID
  atomic_uint64_t total_received;
  atomic_uint64_t general_loss;
  int _maxload;
  bool _clone;
  static String read_handler(Element *, void *) CLICK_COLD;
  int fec_scheme(Packet *p_in, Timestamp now, PacketList &batch, PacketList &builder);
  void store_source_symbol(Packet *p_in, uint32_t encodind_symbol_id);
  void encapsulate_repair_payload(State &s, WritablePacket *p, repair_tlv_t *tlv, uint16_t packet_length);
  WritablePacket *srv6_fec_add_source_tlv(Packet *p_in, source_tlv_t *tlv);
  void rlc_encode_symbols(State &s, uint32_t encoding_symbol_id);
  tinymt32_t rlc_reset_coefs();
  void rlc_fill_muls(uint8_t muls[256 * 256]);
  uint8_t rlc_get_coef(tinymt32_t *prng);
  void rlc_encode_one_symbol(Packet *s, WritablePacket *r, tinymt32_t *prng, uint8_t muls[256 * 256 * sizeof(uint8_t)], repair_tlv_t *repair_tlv);

  void xor_encode_symbols(State &s, uint32_t encoding_symbol_id);
  void xor_encode_one_symbol(Packet *s, WritablePacket *r, repair_tlv_t *repair_tlv);

  void feedback_message(Packet *p_in, std::function<void(Packet *)> push);

  static void click_gf256_init();
  void symbol_add_scaled(void *symbol1, uint8_t coef, const void *symbol2, uint32_t symbol_size, uint8_t *mul);
  void symbol_add_scaled_safe(void *symbol1, uint8_t coef, const void *symbol2, uint32_t symbol_size, uint8_t *mul);
  bool symbol_is_zero(void *symbol, uint32_t symbol_size);
  uint8_t gf256_mul(uint8_t a, uint8_t b, uint8_t *mul);
  uint8_t gf256_mul_formula(uint8_t a, uint8_t b);
  uint8_t gmul(uint8_t a, uint8_t b);

  bool should_send_repair(State &s);
  int do_repair_symbols(State &s);
};

CLICK_ENDDECLS
#endif
