#ifndef CLICK_IP6SRv6FECDecode_HH
#define CLICK_IP6SRv6FECDecode_HH
#include <click/batchelement.hh>
#include <click/glue.hh>
#include <click/atomic.hh>
#include <clicknet/ip6.h>
#include <click/ip6address.hh>
#include <click/batchbuilder.hh>
#include <tinymt32/tinymt32.h>

#define symbol_sub_scaled_term symbol_add_scaled_term

#define RLC_MAX_WINDOWS 100
#define SRV6_FEC_BUFFER_SIZE 1500
#define MAX_WINDOW_SIZE 10000

#ifndef SRV6FEC_HH
#define SRV6FEC_HH

#define TLV_TYPE_FEC_SOURCE 28
#define TLV_TYPE_FEC_REPAIR 29
#define TLV_TYPE_FEC_FEEDBACK 30
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

#define FEEDBACK_TIMELAG 1600
#define FEEDBACK_BUFFER_LENGTH (FEEDBACK_TIMELAG + 100)
#define GRANULARITY 1000

CLICK_DECLS

/*
=c

IP6SRv6FECDecode()

=s ip

Forward Erasure Correction for IPv6 Segment Routing

=d

=e


  IP6SRv6FECDecode(fc00::a, fc00::9)

=a IP6Encap */

struct srv6_fec2_source_t
{
  Packet *p;
  uint32_t encoding_symbol_id;
  uint16_t initial_plen; // Let us determine if the packet changed
  struct in6_addr dst;   // But the destination address should not change (normally)
  uint8_t srv6_next_hdr; // Same here
};

struct srv6_fec2_repair_t
{
  WritablePacket *p;
  repair_tlv_t tlv;
  bool decoded_ind[MAX_WINDOW_SIZE];
};

struct srv6_fec2_term_t
{
  uint8_t *data;
  union
  {
    uint16_t coded_length;
    uint16_t data_length;
  } length;
};

struct srv6_fec2_feedback_t
{
  uint64_t received_string;
  uint32_t nb_received;
  uint32_t esid_last_feedback;
  uint32_t last_received_esid_in_sequence;
  uint32_t most_recent_esi;
  // Indication of the received symbols for this feedback timelag
  bool packet_trace[FEEDBACK_BUFFER_LENGTH];
  uint32_t idx_first_packet_trace;
};

struct feedback_values_t
{
  uint32_t nb_lost;
  uint16_t burst_mean;
  uint16_t burst_std_dev;
};

struct rlc_param_decoder_t
{
  // RLC relative parameters (constants)
  uint8_t muls[256 * 256 * sizeof(uint8_t)];
  uint8_t table_inv[256 * sizeof(uint8_t)];
};

struct rlc_info_decoder_t
{
  // RLC relative information
  tinymt32_t prng;
  srv6_fec2_source_t *source_buffer[SRV6_FEC_BUFFER_SIZE];
  srv6_fec2_repair_t *repair_buffer[SRV6_FEC_BUFFER_SIZE];
  srv6_fec2_source_t *recovd_buffer[SRV6_FEC_BUFFER_SIZE];
  uint32_t encoding_symbol_id; // ESI of the last received repair symbol
  uint32_t esid_last_feedback;
  int nb_unknowns_last_system;
  int nb_equations_last_system;
};

#define SRV6_RLC_MAX_SYMBOLS 1500

struct rlc_recover_utils_t
{
  srv6_fec2_source_t **ss_array;
  srv6_fec2_repair_t **rs_array;
  uint16_t *x_to_source;
  uint16_t *source_to_x;
  bool *protected_symbols;
  uint8_t *coefs;
  srv6_fec2_term_t **unknowns;
  uint8_t **system_coefs;
  srv6_fec2_term_t **constant_terms;
  bool *undetermined;
};

#define SRV6_FEC_RLC 0
#define SRV6_FEC_XOR 1

class IP6SRv6FECDecode : public BatchElement, public Router::InitFuture
{

public:
  IP6SRv6FECDecode();
  ~IP6SRv6FECDecode();

  const char *class_name() const override { return "IP6SRv6FECDecode"; }
  const char *port_count() const override { return "1/1-2"; }

  int configure(Vector<String> &, ErrorHandler *) override CLICK_COLD;
  bool can_live_reconfigure() const override { return true; }
  void add_handlers() override CLICK_COLD;

  int solve_initialize(ErrorHandler *) override CLICK_COLD;

  void push(int, Packet *p_in) override;
#if HAVE_BATCH
  void push_batch(int, PacketBatch *batch_in) override;
#endif

  static void static_initialize();

  void cleanup(CleanupStage stage) override CLICK_COLD;

private:
  atomic_uint64_t total_recovered;
  atomic_uint64_t total_bad_recovered;
  atomic_uint64_t total_system_tried;
  atomic_uint64_t total_system_done;
  atomic_uint64_t total_received_source;
  IP6Address enc;      // Encoder SID
  IP6Address dec;      // Decoder SID
  IP6Address feedback; // Feedback SID
  bool _do_recover;
  bool _minimal_system_fec;
  int _maxload;
  bool _prefetch;
  bool _use_fast;
  bool _clone;
  bool _use_ecn;
  rlc_param_decoder_t _rlc_params;
  Vector<uint32_t> received_ss;
  Vector<uint32_t> received_rs;
  uint64_t total_received_ss;
  uint64_t total_received_rs;

  struct StreamState
  {
    StreamState() : repair_skipped(0), repair_overload(0), repair_before_source(0) {

    }

    rlc_info_decoder_t rlc_info;
    srv6_fec2_feedback_t rlc_feedback;
    click_ip6_sr *white_srv6;
    uint32_t last_window;
    uint16_t white_srv6_total_length;
    rlc_recover_utils_t rlc_utils;
    uint32_t esi_last_in_sequence; // ESI of the last repair symbol in sequence or before which we don't try to recover

    //Stats
    int repair_overload;
    int repair_skipped;
    int repair_before_source;
  };

  Vector<StreamState> _state;

  static String read_handler(Element *, void *) CLICK_COLD;

  void fec_framework(Packet *p_in, std::function<void(Packet *)> push);
  int fec_scheme_source(Packet *p_in, source_tlv_t *tlv, StreamState &s, std::function<void(Packet *)> push);
  void fec_scheme_repair(Packet *p_in, repair_tlv_t *tlv, std::function<void(Packet *)> push, StreamState &s);
  WritablePacket *recover_packet_fom_data(srv6_fec2_term_t *rec, bool is_first_rec);
  srv6_fec2_term_t *init_term(Packet *p, uint16_t offset, uint16_t max_packet_length);
  void kill_term(srv6_fec2_term_t *t);

  void rlc_fill_muls(uint8_t muls[256 * 256]);

  void store_source_symbol(Packet *p_in, source_tlv_t *tlv, StreamState &s);
  void store_repair_symbol(Packet *p_in, repair_tlv_t *tlv, StreamState &s);
  void remove_tlv_source_symbol(WritablePacket *p, uint16_t offset_tlv);

  void rlc_recover_symbols(std::function<void(Packet *)> push, StreamState &s);
  void rlc_get_coefs(tinymt32_t *prng, uint32_t seed, int n, uint8_t *coefs);
  void symbol_add_scaled_term(srv6_fec2_repair_t *symbol1, uint8_t coef, srv6_fec2_source_t *symbol2, uint8_t *mul, uint16_t repair_offset, StreamState &s);
  void symbol_add_scaled_term(srv6_fec2_term_t *symbol1, uint8_t coef, srv6_fec2_term_t *symbol2, uint8_t *mul, uint16_t decoding_size, StreamState &s);
  void symbol_mul_term(srv6_fec2_term_t *symbol1, uint8_t coef, uint8_t *mul, uint16_t size);

  void swap(uint8_t **a, int i, int j);
  void swap_b(srv6_fec2_term_t **a, int i, int j);
  int cmp_eq_i(uint8_t *a, uint8_t *b, int idx, int n_unknowns);
  int cmp_eq(uint8_t *a, uint8_t *b, int idx, int n_unknowns);
  void sort_system(uint8_t **a, srv6_fec2_term_t **constant_terms, int n_eq, int n_unknowns);
  int first_non_zero_idx(const uint8_t *a, int n_unknowns);
  void gauss_elimination(int n_eq, int n_unknowns, uint8_t **a, srv6_fec2_term_t **constant_terms, srv6_fec2_term_t **x, bool *undetermined, uint8_t *mul, uint8_t *inv, uint16_t max_packet_length, StreamState &s);
  void gauss_elimination2(int n_eq, int n_unknowns, uint8_t **a, srv6_fec2_term_t **constant_terms, srv6_fec2_term_t **x, bool *undetermined, uint8_t *mul, uint8_t *inv, uint16_t max_packet_length, StreamState &s);

  void xor_recover_symbols(std::function<void(Packet *)> push, StreamState &s);
  void xor_one_symbol(srv6_fec2_term_t *rec, Packet *s);

  void rlc_feedback(StreamState &s, int stream_id);
  void compute_feedback_trace(StreamState &s, feedback_tlv_t *feedback);

  static void click_gf256_init();
  void symbol_add_scaled(void *symbol1, uint8_t coef, const void *symbol2, uint32_t symbol_size, uint8_t *mul);
  void symbol_add_scaled_safe(void *symbol1, uint8_t coef, const void *symbol2, uint32_t symbol_size, uint8_t *mul);
  bool symbol_is_zero(void *symbol, uint32_t symbol_size);
  void symbol_mul(uint8_t *symbol1, uint8_t coef, uint32_t symbol_size, uint8_t *mul);
  uint8_t gf256_mul(uint8_t a, uint8_t b, uint8_t *mul);
  uint8_t gf256_mul_formula(uint8_t a, uint8_t b);
  void assign_inv(uint8_t *array);

  void echelon_form(int n_eq, int n_unk, uint8_t **a, srv6_fec2_term_t **b, srv6_fec2_term_t **x, uint16_t max_packet_length);
  uint8_t gmul(uint8_t a, uint8_t b);

  uint16_t get_offset_in_source(srv6_fec2_source_t *source);
};

CLICK_ENDDECLS
#endif
