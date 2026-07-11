// Original Work copyright (c) Oleksandr Tkachenko
// Modified Work copyright (c) 2021 Microsoft Research
//
// \author Oleksandr Tkachenko
// \email tkachenko@encrypto.cs.tu-darmstadt.de
// \organization Cryptography and Privacy Engineering Group (ENCRYPTO)
// \TU Darmstadt, Computer Science department
//
// \copyright The MIT License. Copyright Oleksandr Tkachenko
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the Software
// is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
// INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR
// A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
// HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// Modified by Akash Shah

#include <algorithm>
#include <cassert>
#include <iomanip>
#include <iostream>

#include <boost/program_options.hpp>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
#include <thread>

#include <ENCRYPTO_utils/crypto/crypto.h>
#include <ENCRYPTO_utils/parse_options.h>
#include <chrono>
#include "../../Kunlun/crypto/setup.hpp"
#include "../../Kunlun/mpc/oprf/vole_oprf.hpp"
#include "../../Kunlun/mpc/ot/iknp_ote.hpp"
#include "ENCRYPTO_utils/connection.h"
#include "ENCRYPTO_utils/socket.h"
#include "HashingTables/common/hash_table_entry.h"
#include "HashingTables/common/hashing.h"
#include "HashingTables/cuckoo_hashing/cuckoo_hashing.h"
#include "HashingTables/simple_hashing/simple_hashing.h"
#include "abycore/aby/abyparty.h"
#include "common/config.h"
#include "common/functionalities.h"
// #include "triangle.h"
#include "cycle4.h"
string file_name = "./data/neighbor_files_";
uint64_t MAX_DEGREE;
uint64_t NUM_VERTEX;
uint64_t checked_pow2_u64(uint64_t shift)
{
  if (shift >= std::numeric_limits<uint64_t>::digits)
  {
    throw std::invalid_argument("left shift is too large");
  }
  return 1ULL << shift;
}

uint64_t baxos_bin_size_from_log(uint64_t log_value)
{
  uint64_t shift = log_value > 6 ? log_value - 6 : 0;
  shift = std::max<uint64_t>(8, shift);
  return checked_pow2_u64(shift);
}

uint64_t ceil_log2_u64(uint64_t value)
{
  if (value <= 1)
    return 0;

  uint64_t log_value = 0;
  uint64_t power = 1;
  while (power < value)
  {
    power = checked_pow2_u64(++log_value);
  }
  return log_value;
}

const char *role_name(uint32_t role)
{
  if (role == SERVER)
    return "server";
  if (role == CLIENT)
    return "querier";
  return "unknown";
}

uint64_t round_up_to_multiple_u64(uint64_t value, uint64_t multiple)
{
  if (multiple == 0)
  {
    throw std::invalid_argument("multiple must be non-zero");
  }

  uint64_t remainder = value % multiple;
  return remainder == 0 ? value : value + multiple - remainder;
}

uint64_t padded_psi_nbins(uint64_t raw_bin_num)
{
  // uint64_t kMinPsiBins = std::min<uint64_t>(ceil_log2_u64(raw_bin_num), 8);
  // return std::max<uint64_t>(round_up_to_multiple_u64(raw_bin_num, 8), checked_pow2_u64(kMinPsiBins));
  if (raw_bin_num <= 256)
    return std::max<uint64_t>(checked_pow2_u64(ceil_log2_u64(raw_bin_num)), 8);
  else
    return round_up_to_multiple_u64(raw_bin_num, 8);
}

using ProfileClock = std::chrono::steady_clock;

struct CommSnapshot
{
  uint64_t kunlun_sent = 0;
  uint64_t kunlun_recv = 0;
  uint64_t sci_sent = 0;
  uint64_t sci_recv = 0;
  uint64_t libote_sent = 0;
  uint64_t libote_recv = 0;
  uint64_t aby_sent = 0;
  uint64_t aby_recv = 0;
};

struct ProfileRecord
{
  std::string stage;
  uint64_t candidate = std::numeric_limits<uint64_t>::max();
  double elapsed_ms = 0;
  CommSnapshot bytes;
};

class Profiler
{
public:
  Profiler(uint32_t role, std::string dataset, uint64_t query_vertex,
           bool candidate_detail, NetIO *io, NetIO *io2, sci::NetIO *ioArr[3],
           CSocket *sock, osuCrypto::Channel *chl)
      : role_(role),
        dataset_(std::move(dataset)),
        query_vertex_(query_vertex),
        candidate_detail_(candidate_detail),
        io_(io),
        io2_(io2),
        sock_(sock),
        chl_(chl)
  {
    for (int i = 0; i < 3; i++)
    {
      ioArr_[i] = ioArr[i];
    }
  }

  CommSnapshot Capture() const
  {
    CommSnapshot snapshot;
    AddKunlun(snapshot, io_);
    AddKunlun(snapshot, io2_);
    for (int i = 0; i < 3; i++)
    {
      if (ioArr_[i] != nullptr)
      {
        snapshot.sci_sent += ioArr_[i]->counter;
        snapshot.sci_recv += ioArr_[i]->recv_counter;
      }
    }
    if (chl_ != nullptr)
    {
      snapshot.libote_sent = chl_->getTotalDataSent();
      snapshot.libote_recv = chl_->getTotalDataRecv();
    }
    if (sock_ != nullptr)
    {
      snapshot.aby_sent = sock_->getSndCnt();
      snapshot.aby_recv = sock_->getRcvCnt();
    }
    return snapshot;
  }

  void RecordSince(const std::string &stage, uint64_t candidate,
                   ProfileClock::time_point start_time,
                   const CommSnapshot &start_comm)
  {
    const auto end_time = ProfileClock::now();
    const auto end_comm = Capture();
    ProfileRecord record;
    record.stage = stage;
    record.candidate = candidate;
    record.elapsed_ms = std::chrono::duration<double, std::milli>(end_time - start_time).count();
    record.bytes = Diff(end_comm, start_comm);
    records_.push_back(record);
  }

  void Print() const
  {
    if (records_.empty())
    {
      return;
    }

    std::map<std::string, AggregateRecord> aggregates;
    for (const auto &record : records_)
    {
      auto &aggregate = aggregates[record.stage];
      aggregate.calls++;
      aggregate.elapsed_ms += record.elapsed_ms;
      Add(aggregate.bytes, record.bytes);
    }

    const auto old_flags = std::cout.flags();
    const auto old_precision = std::cout.precision();
    std::cout << std::fixed << std::setprecision(3);
    std::cout << "[PROFILE] role=" << role_name(role_)
              << " dataset=" << dataset_
              << " query=" << query_vertex_ << std::endl;
    std::cout << "[PROFILE] aggregate" << std::endl;
    PrintHeader(false);
    for (const auto &stage : StageOrder())
    {
      auto iter = aggregates.find(stage);
      if (iter != aggregates.end())
      {
        PrintAggregateRow(stage, iter->second);
      }
    }
    for (const auto &entry : aggregates)
    {
      if (!IsKnownStage(entry.first))
      {
        PrintAggregateRow(entry.first, entry.second);
      }
    }

    if (candidate_detail_)
    {
      std::cout << "[PROFILE] candidate_detail" << std::endl;
      PrintHeader(true);
      for (const auto &record : records_)
      {
        PrintRecordRow(record);
      }
    }
    std::cout.flags(old_flags);
    std::cout.precision(old_precision);
  }

private:
  struct AggregateRecord
  {
    uint64_t calls = 0;
    double elapsed_ms = 0;
    CommSnapshot bytes;
  };

  static void AddKunlun(CommSnapshot &snapshot, const NetIO *io)
  {
    if (io == nullptr)
    {
      return;
    }
    snapshot.kunlun_sent += io->totalBytesSent;
    snapshot.kunlun_recv += io->totalBytesReceived;
  }

  static uint64_t SubtractCounter(uint64_t end, uint64_t start)
  {
    return end >= start ? end - start : 0;
  }

  static CommSnapshot Diff(const CommSnapshot &end, const CommSnapshot &start)
  {
    CommSnapshot diff;
    diff.kunlun_sent = SubtractCounter(end.kunlun_sent, start.kunlun_sent);
    diff.kunlun_recv = SubtractCounter(end.kunlun_recv, start.kunlun_recv);
    diff.sci_sent = SubtractCounter(end.sci_sent, start.sci_sent);
    diff.sci_recv = SubtractCounter(end.sci_recv, start.sci_recv);
    diff.libote_sent = SubtractCounter(end.libote_sent, start.libote_sent);
    diff.libote_recv = SubtractCounter(end.libote_recv, start.libote_recv);
    diff.aby_sent = SubtractCounter(end.aby_sent, start.aby_sent);
    diff.aby_recv = SubtractCounter(end.aby_recv, start.aby_recv);
    return diff;
  }

  static void Add(CommSnapshot &target, const CommSnapshot &source)
  {
    target.kunlun_sent += source.kunlun_sent;
    target.kunlun_recv += source.kunlun_recv;
    target.sci_sent += source.sci_sent;
    target.sci_recv += source.sci_recv;
    target.libote_sent += source.libote_sent;
    target.libote_recv += source.libote_recv;
    target.aby_sent += source.aby_sent;
    target.aby_recv += source.aby_recv;
  }

  static uint64_t TotalSent(const CommSnapshot &bytes)
  {
    return bytes.kunlun_sent + bytes.sci_sent + bytes.libote_sent + bytes.aby_sent;
  }

  static uint64_t TotalRecv(const CommSnapshot &bytes)
  {
    return bytes.kunlun_recv + bytes.sci_recv + bytes.libote_recv + bytes.aby_recv;
  }

  static double ToMB(uint64_t bytes)
  {
    return bytes / static_cast<double>(1ULL << 20);
  }

  static const std::vector<std::string> &StageOrder()
  {
    static const std::vector<std::string> stages = {
        "prepare_table",
        "vole_oprf",
        "oprf_evaluate",
        "okvs",
        "block_equality",
        "ot_sum",
        "psi_ca_total",
        "beaver_square",
        "term_exchange",
        "final_total_exchange",
        "protocol_total"};
    return stages;
  }

  static bool IsKnownStage(const std::string &stage)
  {
    const auto &stages = StageOrder();
    return std::find(stages.begin(), stages.end(), stage) != stages.end();
  }

  static std::string CandidateLabel(uint64_t candidate)
  {
    if (candidate == std::numeric_limits<uint64_t>::max())
    {
      return "all";
    }
    return std::to_string(candidate);
  }

  static void PrintHeader(bool include_candidate)
  {
    std::cout << std::left << std::setw(22) << "stage";
    if (include_candidate)
    {
      std::cout << std::right << std::setw(12) << "candidate";
    }
    else
    {
      std::cout << std::right << std::setw(8) << "calls";
    }
    std::cout << std::setw(14) << "time_ms"
              << std::setw(12) << "sent_MB"
              << std::setw(12) << "recv_MB"
              << std::setw(12) << "kl_s_MB"
              << std::setw(12) << "kl_r_MB"
              << std::setw(12) << "sci_s_MB"
              << std::setw(12) << "sci_r_MB"
              << std::setw(15) << "libote_s_MB"
              << std::setw(15) << "libote_r_MB"
              << std::setw(12) << "aby_s_MB"
              << std::setw(12) << "aby_r_MB"
              << std::endl;
  }

  static void PrintBytes(const CommSnapshot &bytes)
  {
    std::cout << std::setw(12) << ToMB(TotalSent(bytes))
              << std::setw(12) << ToMB(TotalRecv(bytes))
              << std::setw(12) << ToMB(bytes.kunlun_sent)
              << std::setw(12) << ToMB(bytes.kunlun_recv)
              << std::setw(12) << ToMB(bytes.sci_sent)
              << std::setw(12) << ToMB(bytes.sci_recv)
              << std::setw(15) << ToMB(bytes.libote_sent)
              << std::setw(15) << ToMB(bytes.libote_recv)
              << std::setw(12) << ToMB(bytes.aby_sent)
              << std::setw(12) << ToMB(bytes.aby_recv)
              << std::endl;
  }

  static void PrintAggregateRow(const std::string &stage, const AggregateRecord &record)
  {
    std::cout << std::left << std::setw(22) << stage
              << std::right << std::setw(8) << record.calls
              << std::setw(14) << record.elapsed_ms;
    PrintBytes(record.bytes);
  }

  static void PrintRecordRow(const ProfileRecord &record)
  {
    std::cout << std::left << std::setw(22) << record.stage
              << std::right << std::setw(12) << CandidateLabel(record.candidate)
              << std::setw(14) << record.elapsed_ms;
    PrintBytes(record.bytes);
  }

  uint32_t role_;
  std::string dataset_;
  uint64_t query_vertex_;
  bool candidate_detail_;
  NetIO *io_;
  NetIO *io2_;
  sci::NetIO *ioArr_[3] = {nullptr, nullptr, nullptr};
  CSocket *sock_;
  osuCrypto::Channel *chl_;
  std::vector<ProfileRecord> records_;
};

class ProfileScope
{
public:
  ProfileScope(Profiler *profiler, std::string stage,
               uint64_t candidate = std::numeric_limits<uint64_t>::max())
      : profiler_(profiler),
        stage_(std::move(stage)),
        candidate_(candidate)
  {
    if (profiler_ != nullptr)
    {
      start_comm_ = profiler_->Capture();
      start_time_ = ProfileClock::now();
      active_ = true;
    }
  }

  ~ProfileScope()
  {
    if (!active_)
    {
      return;
    }
    try
    {
      profiler_->RecordSince(stage_, candidate_, start_time_, start_comm_);
    }
    catch (...)
    {
    }
  }

  ProfileScope(const ProfileScope &) = delete;
  ProfileScope &operator=(const ProfileScope &) = delete;

private:
  Profiler *profiler_ = nullptr;
  std::string stage_;
  uint64_t candidate_ = std::numeric_limits<uint64_t>::max();
  ProfileClock::time_point start_time_;
  CommSnapshot start_comm_;
  bool active_ = false;
};

// https://stackoverflow.com/questions/24161243/how-can-i-add-together-two-sse-registers
inline block unsigned_lessthan(block a, block b)
{
#ifdef __XOP__ // AMD XOP instruction set
  return _mm_comgt_epu64(b, a);
#else // SSE2 instruction set
  block sign32 = _mm_set1_epi32(0x80000000);       // sign bit of each dword
  block aflip = _mm_xor_si128(b, sign32);          // a with sign bits flipped
  block bflip = _mm_xor_si128(a, sign32);          // b with sign bits flipped
  block equal = _mm_cmpeq_epi32(b, a);             // a == b, dwords
  block bigger = _mm_cmpgt_epi32(aflip, bflip);    // a > b, dwords
  block biggerl = _mm_shuffle_epi32(bigger, 0xA0); // a > b, low dwords copied to high dwords
  block eqbig = _mm_and_si128(equal, biggerl);     // high part equal and low part bigger
  block hibig = _mm_or_si128(bigger, eqbig);       // high part bigger or high part equal and low part
  block big = _mm_shuffle_epi32(hibig, 0xF5);      // result copied to low part
  return big;
#endif
}
block add_with_carry(block x, block y)
{
  // 执行加法操作
  block z = _mm_add_epi64(x, y);

  // 计算进位
  block c = _mm_unpacklo_epi64(_mm_setzero_si128(), unsigned_lessthan(z, x));

  // 处理进位
  z = _mm_sub_epi64(z, c);

  return z;
}
block mul_mod_2_128(block x, block y)
{
  uint64_t x_low = static_cast<uint64_t>(_mm_cvtsi128_si64(x));
  uint64_t x_high = static_cast<uint64_t>(_mm_extract_epi64(x, 1));
  uint64_t y_low = static_cast<uint64_t>(_mm_cvtsi128_si64(y));
  uint64_t y_high = static_cast<uint64_t>(_mm_extract_epi64(y, 1));

  __uint128_t low_product = static_cast<__uint128_t>(x_low) * y_low;
  uint64_t low = static_cast<uint64_t>(low_product);
  uint64_t high = static_cast<uint64_t>(low_product >> 64);

  high += x_low * y_high;
  high += x_high * y_low;

  return Block::MakeBlock(high, low);
}
block invert_block(block a)
{
  // 对__m128i寄存器中的每个元素进行按位取反
  // 创建一个全1的掩码
  block mask = _mm_cmpeq_epi32(_mm_setzero_si128(), _mm_setzero_si128());
  // 对a执行按位异或运算，即取反操作
  return _mm_xor_si128(a, mask);
}
block sub_with_borrow(block x, block y)
{
  block opposite = add_with_carry(invert_block(y), Block::MakeBlock(0, 1));
  return add_with_carry(x, opposite);
}

block neg_mod_2_128(block x)
{
  return sub_with_borrow(Block::zero_block, x);
}

block shl_mod_2_128(block x, uint32_t shift)
{
  if (shift == 0)
    return x;
  if (shift >= 128)
    return Block::zero_block;

  uint64_t low = static_cast<uint64_t>(_mm_cvtsi128_si64(x));
  uint64_t high = static_cast<uint64_t>(_mm_extract_epi64(x, 1));

  if (shift < 64)
  {
    high = (high << shift) | (low >> (64 - shift));
    low <<= shift;
  }
  else
  {
    high = low << (shift - 64);
    low = 0;
  }

  return Block::MakeBlock(high, low);
}

uint8_t get_block_bit(block x, uint32_t bit_idx)
{
  uint64_t word = bit_idx < 64
                      ? static_cast<uint64_t>(_mm_cvtsi128_si64(x))
                      : static_cast<uint64_t>(_mm_extract_epi64(x, 1));
  return static_cast<uint8_t>((word >> (bit_idx & 63)) & 1);
}

struct BeaverTripleShare128
{
  std::vector<block> a;
  std::vector<block> b;
  std::vector<block> c;
};

std::vector<block> iknp_ole_sender_128(NetIO &io, IKNPOTE::PP &pp,
                                       const std::vector<block> &x,
                                       size_t start, size_t count,
                                       PRG::Seed &seed)
{
  constexpr size_t kRingBits = 128;
  size_t ot_len = count * kRingBits;
  std::vector<block> m0 = PRG::GenRandomBlocks(seed, ot_len);
  std::vector<block> m1(ot_len);
  std::vector<block> sender_share(count, Block::zero_block);

  for (size_t i = 0; i < count; i++)
  {
    block mask_sum = Block::zero_block;
    for (uint32_t bit = 0; bit < kRingBits; bit++)
    {
      size_t ot_idx = i * kRingBits + bit;
      mask_sum = add_with_carry(mask_sum, m0[ot_idx]);
      m1[ot_idx] = add_with_carry(m0[ot_idx], shl_mod_2_128(x[start + i], bit));
    }
    sender_share[i] = neg_mod_2_128(mask_sum);
  }

  IKNPOTE::Send(io, pp, m0, m1, ot_len);
  return sender_share;
}

std::vector<block> iknp_ole_receiver_128(NetIO &io, IKNPOTE::PP &pp,
                                         const std::vector<block> &y,
                                         size_t start, size_t count)
{
  constexpr size_t kRingBits = 128;
  size_t ot_len = count * kRingBits;
  std::vector<uint8_t> choices(ot_len);

  for (size_t i = 0; i < count; i++)
  {
    for (uint32_t bit = 0; bit < kRingBits; bit++)
    {
      choices[i * kRingBits + bit] = get_block_bit(y[start + i], bit);
    }
  }

  std::vector<block> selected = IKNPOTE::Receive(io, pp, choices, ot_len);
  std::vector<block> receiver_share(count, Block::zero_block);
  for (size_t i = 0; i < count; i++)
  {
    block sum = Block::zero_block;
    for (uint32_t bit = 0; bit < kRingBits; bit++)
    {
      sum = add_with_carry(sum, selected[i * kRingBits + bit]);
    }
    receiver_share[i] = sum;
  }

  return receiver_share;
}

std::vector<block> iknp_ole_product_share_128(NetIO &io, bool local_is_sender,
                                              const std::vector<block> &input,
                                              PRG::Seed &seed)
{
  constexpr size_t kBaseOtNum = 128;
  constexpr size_t kBatchTriples = 1024;
  std::vector<block> shares(input.size(), Block::zero_block);
  auto pp = IKNPOTE::Setup(kBaseOtNum);

  for (size_t start = 0; start < input.size(); start += kBatchTriples)
  {
    size_t count = std::min(kBatchTriples, input.size() - start);
    std::vector<block> batch_share;
    if (local_is_sender)
    {
      batch_share = iknp_ole_sender_128(io, pp, input, start, count, seed);
    }
    else
    {
      batch_share = iknp_ole_receiver_128(io, pp, input, start, count);
    }
    std::copy(batch_share.begin(), batch_share.end(), shares.begin() + start);
  }

  return shares;
}

BeaverTripleShare128 generate_beaver_triples_128(uint32_t role, NetIO &io,
                                                 size_t num_triples)
{
  if (role != SERVER && role != CLIENT)
  {
    throw std::invalid_argument("generate_beaver_triples_128 requires SERVER or CLIENT role");
  }

  BeaverTripleShare128 triples;
  PRG::Seed seed = PRG::SetSeed(nullptr, 0);
  triples.a = PRG::GenRandomBlocks(seed, num_triples);
  triples.b = PRG::GenRandomBlocks(seed, num_triples);

  std::vector<block> share_a0b1;
  std::vector<block> share_a1b0;
  if (role == SERVER)
  {
    share_a0b1 = iknp_ole_product_share_128(io, true, triples.a, seed);
    share_a1b0 = iknp_ole_product_share_128(io, false, triples.b, seed);
  }
  else
  {
    share_a0b1 = iknp_ole_product_share_128(io, false, triples.b, seed);
    share_a1b0 = iknp_ole_product_share_128(io, true, triples.a, seed);
  }

  triples.c.resize(num_triples);
  for (size_t i = 0; i < num_triples; i++)
  {
    block c_share = mul_mod_2_128(triples.a[i], triples.b[i]);
    c_share = add_with_carry(c_share, share_a0b1[i]);
    c_share = add_with_carry(c_share, share_a1b0[i]);
    triples.c[i] = c_share;
  }

  return triples;
}

block beaver_mul_share_128(block x_share, block y_share,
                           const BeaverTripleShare128 &triples,
                           size_t triple_idx, uint32_t role, NetIO &io)
{
  if (role != SERVER && role != CLIENT)
  {
    throw std::invalid_argument("beaver_mul_share_128 requires SERVER or CLIENT role");
  }
  if (triple_idx >= triples.a.size() || triple_idx >= triples.b.size() ||
      triple_idx >= triples.c.size())
  {
    throw std::out_of_range("beaver_mul_share_128 triple index is out of range");
  }

  block d_share = sub_with_borrow(x_share, triples.a[triple_idx]);
  block e_share = sub_with_borrow(y_share, triples.b[triple_idx]);
  block peer_d_share;
  block peer_e_share;

  if (role == SERVER)
  {
    io.SendBlock(d_share);
    io.SendBlock(e_share);
    io.ReceiveBlock(peer_d_share);
    io.ReceiveBlock(peer_e_share);
  }
  else
  {
    io.ReceiveBlock(peer_d_share);
    io.ReceiveBlock(peer_e_share);
    io.SendBlock(d_share);
    io.SendBlock(e_share);
  }

  block d = add_with_carry(d_share, peer_d_share);
  block e = add_with_carry(e_share, peer_e_share);
  block z_share = triples.c[triple_idx];
  z_share = add_with_carry(z_share, mul_mod_2_128(d, triples.b[triple_idx]));
  z_share = add_with_carry(z_share, mul_mod_2_128(e, triples.a[triple_idx]));
  if (role == SERVER)
  {
    z_share = add_with_carry(z_share, mul_mod_2_128(d, e));
  }

  return z_share;
}
struct VOLEOPRFTestCase
{
  std::vector<block> vec_Y; // client set
  std::vector<block> vec_Fk_Y;
  size_t INPUT_NUM; // size of set
};

VOLEOPRFTestCase GenTestCase(size_t LOG_INPUT_NUM)
{
  VOLEOPRFTestCase testcase;
  testcase.INPUT_NUM = checked_pow2_u64(LOG_INPUT_NUM);

  PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
  testcase.vec_Y = PRG::GenRandomBlocks(seed, testcase.INPUT_NUM);

  return testcase;
}
std::vector<uint8_t> oprf_server(NetIO &io)
{
  CRYPTO_Initialize();

  VOLEOPRF::PP pp;

  pp = VOLEOPRF::Setup(7); // 40 is the statistical parameter

  std::vector<uint8_t> oprf_key = VOLEOPRF::Server1(io, pp);

  return oprf_key;
}
std::vector<block> oprf_evaluate(std::vector<block> vec, std::vector<uint8_t> oprf_key)
{
  VOLEOPRF::PP pp;

  pp = VOLEOPRF::Setup(7); // 40 is the statistical parameter
  auto vec_Fk_X = VOLEOPRF::Evaluate1(pp, oprf_key, vec, vec.size());
  return vec_Fk_X;
}
std::vector<block> oprf_client(std::vector<block> vec, NetIO &io)
{
  CRYPTO_Initialize();

  VOLEOPRF::PP pp;

  pp = VOLEOPRF::Setup(7); // 40 is the statistical parameter

  std::vector<block> vec_Fk_Y = VOLEOPRF::Client1(io, pp, vec, pp.INPUT_NUM);
  return vec_Fk_Y;
}
size_t countDuplicates(const std::vector<uint64_t> &vec)
{
  std::unordered_map<uint64_t, size_t> elementCount;
  for (const auto &elem : vec)
  {
    ++elementCount[elem];
  }

  size_t duplicateCount = 0;
  for (const auto &pair : elementCount)
  {
    if (pair.second > 1)
    {
      duplicateCount += pair.second - 1;
    }
  }

  return duplicateCount;
}
block psi_ca_receiver(std::vector<block> &set, uint64_t candidate_idx, ENCRYPTO::PsiAnalyticsContext &context, std::unique_ptr<CSocket> &sock,
                     sci::NetIO *ioArr[3], osuCrypto::Channel &chl, NetIO &io, NetIO &io2,
                     Profiler *profiler = nullptr)
{
  VOLEOPRF::PP pp;
  uint64_t nbins = 0;
  PRG::Seed seed = PRG::SetSeed(); // initialize PRG
  std::vector<uint64_t> idxs;
  std::vector<block> cuckoo_table_v;
  {
    ProfileScope profile_scope(profiler, "prepare_table", candidate_idx);
    uint64_t bin_num = MAX_DEGREE * 1.27;
    // pp = VOLEOPRF::Setup(ceil_log2_u64(bin_num));
    // std::cout << "!!!!" << bin_num << " " << pp.INPUT_NUM << std::endl;
    nbins = padded_psi_nbins(bin_num);
    // std::cout << "print:" << MAX_DEGREE << " " << bin_num << " " << nbins << std::endl;
    pp = VOLEOPRF::Setup(ceil_log2_u64(nbins));
    io.SendBytes(&nbins, 8);
    std::vector<uint64_t> vec;
    std::vector<uint64_t> values;
    std::unordered_map<uint64_t, uint64_t> map;
    for (auto i = 0; i < MAX_DEGREE; i++)
    {
      uint64_t low = ((uint64_t *)(&set[i]))[0];
      uint64_t high = ((uint64_t *)(&set[i]))[1];
      vec.emplace_back(low ^ high);
      values.emplace_back(1);
      map[vec[i]] = values[i];
      // std::cout<<low<<"+"<<high<<" ";
    }

    // std::cout << countDuplicates(vec) << std::endl;
    ENCRYPTO::CuckooTable cuckoo_table(static_cast<std::size_t>(nbins));
    cuckoo_table.SetNumOfHashFunctions(context.nfuns);
    cuckoo_table.Insert(vec);
    cuckoo_table.MapElements();
    // auto add = cuckoo_table.GetElementAddresses();
    if (cuckoo_table.GetStashSize() > 0u)
    {
      std::cerr << "[Error] Stash of size " << cuckoo_table.GetStashSize() << " occured\n";
    }
    auto idx_cuckoo_table = cuckoo_table.AsRawVectorNoID();
    idxs = std::get<0>(idx_cuckoo_table);
    cuckoo_table_v = std::get<1>(idx_cuckoo_table);
    vec.clear();
    vec.shrink_to_fit();
  }
  // oprf
  // std::cout<<"begin oprf client:"<<std::endl;
  std::vector<block> result;
  {
    ProfileScope profile_scope(profiler, "vole_oprf", candidate_idx);

    result = VOLEOPRF::Client1(io, pp, cuckoo_table_v, cuckoo_table_v.size());
 
  }
  
  std::vector<block> eq_blocks(nbins, Block::zero_block);
  {
    ProfileScope profile_scope(profiler, "okvs", candidate_idx);
    // std::cout << "Reach first Baxos\n";
    const auto degree_log = ceil_log2_u64(MAX_DEGREE);
    auto first_baxos_bin_size = baxos_bin_size_from_log(degree_log);
    // std::cout << MAX_DEGREE  * 3 << " " << first_baxos_bin_size << std::endl;
    Baxos<gf_128> baxos(MAX_DEGREE * 3, first_baxos_bin_size, 3);
    // std::cout << "Pass first Baxos\n";
    uint64_t tmp;
    io2.ReceiveInteger(tmp);
    // std::cout << baxos.total_size * baxos.bin_num << std::endl;
    std::vector<block> okvs(baxos.total_size * baxos.bin_num, Block::zero_block);
    // std::cout << "begin receive okvs:" << std::endl;

    io2.ReceiveBlocks(okvs.data(), okvs.size());
    // Block::PrintBlocks(cuckoo_table_v);

    // std::cout << "begin eq:" << std::endl;
    std::vector<block> decode_result(cuckoo_table_v.size());

    baxos.decode(cuckoo_table_v, decode_result, okvs, 8);

    // Block::PrintBlock(decode_result[0]);
    // Block::PrintBlock(decode_result[1]);
    // // decode OKVS

    for (auto i = 0; i < cuckoo_table_v.size(); i++)
    {
      decode_result[i] ^= result[i];
    }

    for (auto i = 0; i < idxs.size(); i++)
      eq_blocks[idxs[i]] = decode_result[idxs[i]];
  }
  // Block::PrintBlocks(eq_blocks);
  // decode_result.clear();
  // decode_result.shrink_to_fit();
  // cuckoo_table.~CuckooTable();

  // result.clear();
  // result.shrink_to_fit();
  // baxos.~Baxos();
  // pp.~PP();
  std::vector<uint8_t> ans;
  {
    ProfileScope profile_scope(profiler, "block_equality", candidate_idx);
    ans = perform_block_equality(eq_blocks, context, sock, ioArr, chl);
  }

  block psi_ca_ans = Block::zero_block;
  {
    ProfileScope profile_scope(profiler, "ot_sum", candidate_idx);
    auto ot_r = PRG::GenRandomBlocks(seed, nbins);
    std::vector<std::vector<block>> ot(2);
    ot[0].reserve(nbins);
    ot[1].reserve(nbins);
    auto sum = 0;
    // auto ck = std::get<1>(idx_cuckoo_table);
    for (auto i = 0, j = 0; i < nbins; i++)
    {
      uint64_t tmp = 1;
      auto block_0 = Block::MakeBlock(0, tmp);
      ot[ans[i]].emplace_back(ot_r[i]);
      // if (j < idxs.size() && i == idxs[j])
      // {
      //   auto tmp = map[((uint64_t *)(&ck[idxs[j]]))[0]];
      //   // std::cout << tmp << std::endl;

      //   block_0 = Block::MakeBlock(0, tmp);
      //   sum += tmp;
      //   j++;
      // }
      ot[1 - ans[i]].emplace_back(add_with_carry(ot_r[i], block_0));
    }
    // std::cout << sum << std::endl;
    for (auto i = 0; i < 128 - nbins % 128; i++)
    {
      ot[0].emplace_back(Block::zero_block);
      ot[1].emplace_back(Block::zero_block);
    }
    auto pp_ot = IKNPOTE::Setup(BASE_LEN);
    // std::cout << nbins + (128 - nbins % 128) << " " << ot[0].size() << " " << ot[1].size()
    //           << std::endl;
    IKNPOTE::Send(io2, pp_ot, ot[0], ot[1], nbins + (128 - nbins % 128));
    for (auto i = 0; i < nbins; i++)
    {
      psi_ca_ans = add_with_carry(psi_ca_ans, ot[ans[i]][i]);
    }
  }
  // Block::PrintBlock(psi_ca_ans);
  // io2.SendBlock(psi_ca_ans);

  return neg_mod_2_128(psi_ca_ans);
}
#include "../../Kunlun/crypto/aes.hpp"
void send_baxos(NetIO &io, std::vector<block> &key, std::vector<block> &value, uint64_t baxos_size, uint64_t num)
{
  if (key.size() != value.size())
  {
    throw std::runtime_error("send_baxos requires key.size() == value.size()");
  }
  if (key.size() > baxos_size)
  {
    throw std::runtime_error("send_baxos key count exceeds baxos capacity");
  }

  // test_baxos_block();
  // auto tmp=get_baxos_block(key,value);
  // std::cout << "Reach send_baxos\n";
  auto send_baxos_bin_size = baxos_bin_size_from_log(num);
  // std::cout << baxos_size << " " << send_baxos_bin_size << std::endl;
  Baxos<gf_128> baxos(baxos_size, send_baxos_bin_size, 3);
  // std::cout << "Pass send_baxos\n";
  // std::cout << baxos.bin_num * baxos.total_size << std::endl;
  std::vector<block> encode_result(baxos.bin_num * baxos.total_size);
  // std::cout << "begin solve" << key.size() << " " << value.size() << " " << encode_result.size() << std::endl;
  constexpr int kMaxBaxosRetries = 20;
  bool solved = false;
  for (int attempt = 0; attempt < kMaxBaxosRetries && !solved; attempt++)
  {
    try
    {
      auto seed = PRG::SetSeed();
      baxos.solve(key, value, encode_result, &seed, 8);
      solved = true;
    }
    catch (const char *e)
    {
      std::cerr << "send_baxos Baxos solve failed: " << e
                << ", retry=" << attempt + 1 << "/" << kMaxBaxosRetries << std::endl;
    }
    catch (const std::exception &e)
    {
      std::cerr << "send_baxos Baxos solve failed: " << e.what()
                << ", retry=" << attempt + 1 << "/" << kMaxBaxosRetries << std::endl;
    }
  }
  if (!solved)
  {
    throw std::runtime_error("send_baxos Baxos solve failed after retries");
  }
  // std::cout << "end solve" << std::endl;
  io.SendInteger(baxos_size);
  io.SendBlocks(encode_result.data(), encode_result.size());
}

block psi_ca_sender(std::vector<block> &set, uint64_t candidate_idx, ENCRYPTO::PsiAnalyticsContext &context, std::unique_ptr<CSocket> &sock,
                   sci::NetIO *ioArr[3], osuCrypto::Channel &chl, NetIO &io, NetIO &io2,
                   Profiler *profiler = nullptr)
{
  // test_baxos_block();
  VOLEOPRF::PP pp;
  PRG::Seed seed = PRG::SetSeed(fixed_seed, 0); // initialize PRG
  uint64_t nbins = 0;
  std::vector<std::vector<block>> simple_table_vec;
  std::vector<block> random_values;
  std::vector<block> simple_table_1d;
  {
    ProfileScope profile_scope(profiler, "prepare_table", candidate_idx);

    io.ReceiveBytes(&nbins, 8);
    pp = VOLEOPRF::Setup(ceil_log2_u64(nbins));
    std::vector<uint64_t> vec;
    for (auto i = 0; i < MAX_DEGREE; i++)
    {
      uint64_t low = ((uint64_t *)(&set[i]))[0];
      uint64_t high = ((uint64_t *)(&set[i]))[1];
      vec.emplace_back(low ^ high);
    }

    random_values = PRG::GenRandomBlocks(seed, nbins);

    ENCRYPTO::SimpleTable simple_table(static_cast<std::size_t>(nbins));
    simple_table.SetNumOfHashFunctions(context.nfuns);
    simple_table.Insert(vec);
    auto simple_table_size = simple_table.AsRaw2DVectorNoID();
    simple_table_vec = std::get<0>(simple_table_size);
    simple_table_1d.reserve(MAX_DEGREE);
    for (auto &row : simple_table_vec)
    {
      simple_table_1d.insert(simple_table_1d.end(), row.begin(), row.end());
    }
  }

  std::vector<uint8_t> oprf_key;
  {
    ProfileScope profile_scope(profiler, "vole_oprf", candidate_idx);

    oprf_key = VOLEOPRF::Server1(io, pp);
  }

  std::vector<block> oprf_result;
  {
    ProfileScope profile_scope(profiler, "oprf_evaluate", candidate_idx);

    oprf_result = VOLEOPRF::Evaluate1(pp, oprf_key, simple_table_1d, simple_table_1d.size());
    auto tmp = 0;
    // std::cout<<"end evaluate"<<std::endl;s
    // getchar();
    // Block::PrintBlocks(simple_table_vec[0]);
    // getchar();
    for (auto i = 0; i < simple_table_vec.size(); i++)
    {
      std::vector<block> &v = simple_table_vec[i];
      // key_okvs.insert(key_okvs.end(), v.begin(), v.end());
      // Block::PrintBlocks(simple_table_vec[i]);
      // std::cout << "----------------------" << i << "------------------------" << std::endl;
      // Block::PrintBlocks(oprf_result);
      for (auto j = 0; j < v.size(); j++, tmp++)
      {
        oprf_result[tmp] = (random_values[i] ^ oprf_result[tmp]);
      }
      v.clear();
      v.shrink_to_fit();
      // if (i % 1000 == 0)
      //   std::cout << "----------------------" << i << "------------------------" << std::endl;
    }
    simple_table_vec.clear();
    simple_table_vec.shrink_to_fit();
  }
  uint64_t baxos_size = MAX_DEGREE * 3;
  // io.SendBytes(&baxos_size, 8);

  // std::vector<block> k=PRG::GenRandomBlocks(seed,MAX_DEGREE*NUM_VERTEX*3);
  // std::vector<block> v=PRG::GenRandomBlocks(seed,MAX_DEGREE*NUM_VERTEX*3);
  {
    ProfileScope profile_scope(profiler, "okvs", candidate_idx);

    send_baxos(io2, simple_table_1d, oprf_result, MAX_DEGREE * 3, ceil_log2_u64(MAX_DEGREE));
    
  }
  simple_table_1d.clear();
  simple_table_1d.shrink_to_fit();
  oprf_result.clear();
  oprf_result.shrink_to_fit();

  std::vector<uint8_t> ans;
  {
    ProfileScope profile_scope(profiler, "block_equality", candidate_idx);
    ans = perform_block_equality(random_values, context, sock, ioArr, chl);
  }

  block psi_ca_ans = Block::zero_block;
  {
    ProfileScope profile_scope(profiler, "ot_sum", candidate_idx);
    auto pp_ot = IKNPOTE::Setup(BASE_LEN);
    for (auto i = 0; i < 128 - nbins % 128; i++)
      ans.emplace_back(0);
    // std::cout << nbins + (128 - nbins % 128) << " " << ans.size() << std::endl;
    std::vector<block> vec_result_real = IKNPOTE::Receive(io2, pp_ot, ans, ans.size());
    // Block::PrintBlocks(vec_result_real);
    for (auto i = 0; i < nbins; i++)
    {
      psi_ca_ans = add_with_carry(psi_ca_ans, vec_result_real[i]);
    }
  }
  // io2.SendBlock(psi_ca_ans);

  // block psi_ca_tmp;
  // io2.ReceiveBlock(psi_ca_tmp);
  // auto block_ans = sub_with_borrow(psi_ca_ans, psi_ca_tmp);
  // Block::PrintBlock(block_ans);
  // std::cout << ((uint64_t *)(&block_ans))[0] << std::endl;
  return psi_ca_ans;
}

struct CommandLineResult
{
  ENCRYPTO::PsiAnalyticsContext context;
  uint64_t x_value;
  uint64_t n_value;
  std::string name;
  std::string task;
  std::string data_dir;
  uint64_t degree_bound;
  bool dry_run;
  bool step4;
  bool step5;
  bool role_supplied;
  bool profile;
  bool profile_candidate_detail;
};
CommandLineResult read_test_options(int argc, char *argv[])
{
  namespace po = boost::program_options;
  ENCRYPTO::PsiAnalyticsContext context;
  po::options_description allowed("Allowed options");
  std::string type;
  std::string task;
  std::string data_dir;
  uint64_t degree_bound = std::numeric_limits<uint64_t>::max();
  bool role_supplied = false;
  for (int i = 1; i < argc; ++i)
  {
    const std::string arg(argv[i]);
    if (arg == "--role" || arg == "-r" || arg.rfind("--role=", 0) == 0)
    {
      role_supplied = true;
    }
  }

  // clang-format off
  allowed.add_options()
    ("help,h", "Produce help message")
    ("neighbor", po::value<uint64_t>()->default_value(std::numeric_limits<uint64_t>::max()), "Value for neighbor (default: UINT64_MAX)")
    ("idx", po::value<uint64_t>()->default_value(std::numeric_limits<uint64_t>::max()), "Value for idx (default: UINT64_MAX)")
    ("num_d", po::value<uint64_t>()->default_value(std::numeric_limits<uint64_t>::max()), "Value for idx (default: UINT64_MAX)")
    ("num_v", po::value<uint64_t>()->default_value(std::numeric_limits<uint64_t>::max()), "Value for idx (default: UINT64_MAX)")
    ("role,r", po::value<decltype(context.role)>(&context.role)->default_value(CLIENT), "Role of the node")
    ("name", po::value<std::string>()->default_value(""), "Value for neighbor (default: UINT64_MAX)")
    ("task", po::value<std::string>(&task)->default_value(""), "Task selector; use cycle4 with --dry-run for 4-cycle layout checks")
    ("data-dir", po::value<std::string>(&data_dir)->default_value(""), "Directory containing neighbor_<node>.txt files")
    ("degree-bound", po::value<uint64_t>(&degree_bound)->default_value(std::numeric_limits<uint64_t>::max()), "Degree bound D for padded 4-cycle query lists")
    ("dry-run", po::bool_switch()->default_value(false), "Build and print 4-cycle dry-run layout without running PSI")
    ("step4", po::bool_switch()->default_value(false), "Run the Step 4 per-candidate dry-run loop")
    ("step5", po::bool_switch()->default_value(false), "Run the Step 5 padded query-list dry-run")
    ("profile", po::bool_switch()->default_value(false), "Print per-stage runtime and communication profiling for the main PSI flow")
    ("profile-candidate-detail", po::bool_switch()->default_value(false), "Print per-candidate profiling rows in addition to aggregate profiling")
    ("neles,n", po::value<decltype(context.neles)>(&context.neles)->default_value(4096u), "Number of my elements")
    ("bit-length,b", po::value<decltype(context.bitlen)>(&context.bitlen)->default_value(62u), "Bit-length of the elements")
    ("epsilon,e", po::value<decltype(context.epsilon)>(&context.epsilon)->default_value(1.27f), "Epsilon, a table size multiplier")
    ("hint-epsilon,E", po::value<decltype(context.fepsilon)>(&context.fepsilon)->default_value(1.27f), "Epsilon, a hint table size multiplier")
    ("address,a", po::value<decltype(context.address)>(&context.address)->default_value("127.0.0.1"), "IP address of the server")
    ("port,p", po::value<decltype(context.port)>(&context.port)->default_value(7777), "Port of the server")
    ("radix,m", po::value<decltype(context.radix)>(&context.radix)->default_value(5u), "Radix in PSM Protocol")
    ("functions,f", po::value<decltype(context.nfuns)>(&context.nfuns)->default_value(3u), "Number of hash functions in hash tables")
    ("hint-functions,F", po::value<decltype(context.ffuns)>(&context.ffuns)->default_value(3u), "Number of hash functions in hint hash tables")
    ("psm-type,y", po::value<std::string>(&type)->default_value("PSM1"), "PSM type {PSM1, PSM2}");
  // clang-format on

  po::variables_map vm;
  try
  {
    po::store(po::parse_command_line(argc, argv, allowed), vm);
    po::notify(vm);
  }
  catch (const boost::exception_detail::clone_impl<boost::exception_detail::error_info_injector<
             boost::program_options::required_option>> &e)
  {
    if (!vm.count("help"))
    {
      std::cout << e.what() << std::endl;
      std::cout << allowed << std::endl;
      exit(EXIT_FAILURE);
    }
  }

  if (vm.count("help"))
  {
    std::cout << allowed << "\n";
    exit(EXIT_SUCCESS);
  }

  if (type.compare("PSM1") == 0)
  {
    context.psm_type = ENCRYPTO::PsiAnalyticsContext::PSM1;
  }
  else if (type.compare("PSM2") == 0)
  {
    context.psm_type = ENCRYPTO::PsiAnalyticsContext::PSM2;
  }
  else
  {
    std::string error_msg(std::string("Unknown PSM type: " + type));
    throw std::runtime_error(error_msg.c_str());
  }

  context.nbins = context.neles * context.epsilon;
  context.fbins = context.fepsilon * context.neles * context.nfuns;

  uint64_t x_value = std::numeric_limits<uint64_t>::max();
  if (vm.count("idx"))
  {
    x_value = vm["idx"].as<uint64_t>();
  }

  uint64_t n_value = std::numeric_limits<uint64_t>::max();
  if (vm.count("neighbor"))
  {
    n_value = vm["neighbor"].as<uint64_t>();
  }
  std::string name = "";
  if (vm.count("neighbor"))
  {
    name = vm["name"].as<std::string>();
  }
  if (vm.count("num_d"))
  {
    MAX_DEGREE = vm["num_d"].as<uint64_t>();
  }
  if (vm.count("num_v"))
  {
    NUM_VERTEX = vm["num_v"].as<uint64_t>();
  }
  return {context,
          x_value,
          n_value,
          name,
          task,
          data_dir,
          degree_bound,
          vm["dry-run"].as<bool>(),
          vm["step4"].as<bool>(),
          vm["step5"].as<bool>(),
          role_supplied,
          vm["profile"].as<bool>(),
          vm["profile-candidate-detail"].as<bool>()};
}

void printFileContent(const std::string &filename)
{
  // open the file
  std::ifstream infile(filename);

  // check if the file is opened successfully
  if (!infile.is_open())
  {
    std::cerr << "无法打开文件: " << filename << std::endl;
    return;
  }

  // read the file content
  std::string line;
  std::cout << "内容 " << filename << ":" << std::endl;
  while (std::getline(infile, line))
  {
    // print the lines
    std::cout << line << std::endl;
  }

  // close the file
  infile.close();
  std::cout << std::endl;
}
void send_test()
{
  NetIO io("client", "127.0.0.1", 8085);
  std::vector<block> tmp(MAX_DEGREE);
  io.SendBlocks(tmp.data(), MAX_DEGREE);
  auto time = io.get_time_statistics();
  // std::cout << "send_time=" << std::get<0>(time) << "recv_time=" << std::get<1>(time) << "recv_time_wait=" << std::get<2>(time) << std::endl;
}
void recv_test()
{
  NetIO io("server", "", 8085);
  std::vector<block> tmp(MAX_DEGREE);
  io.ReceiveBlocks(tmp.data(), MAX_DEGREE);
  auto time = io.get_time_statistics();
  // std::cout << "send_time=" << std::get<0>(time) << "recv_time=" << std::get<1>(time) << "recv_time_wait=" << std::get<2>(time) << std::endl;
}
int main(int argc, char **argv)
{
  auto options = read_test_options(argc, argv);
  file_name += options.name;
  file_name += "/";

  uint64_t x_value = options.x_value;
  uint64_t n_value = options.n_value;
  auto context = options.context;

  std::vector<block> neighbors;
  if (x_value != std::numeric_limits<uint64_t>::max())
    neighbors = read_to_block(file_name + "neighbor_" + std::to_string(x_value) + ".txt");

  std::vector<std::vector<block>> set;
  set = test_request(context.role, x_value, n_value, neighbors);
  if (set.size() == 0)
    return 0;
  // std::cout << "over" << context.role << std::endl;
  // test_baxos_block();
  // return 0;
  CRYPTO_Initialize();
  // getchar();
  // test_baxos_block();
  // baxos.decode(key_set, decode_result, encode_result, thread_num);
  // std::cout<<"over"<<std::endl;

  auto gen_bitlen = static_cast<std::size_t>(std::ceil(std::log2(context.neles))) + 3;

  // Setup Connection
  std::unique_ptr<CSocket> sock = ENCRYPTO::EstablishConnection(context.address, context.port,
                                                                static_cast<e_role>(context.role));
  sci::NetIO *ioArr[3] = {nullptr, nullptr, nullptr};
  osuCrypto::IOService ios;
  osuCrypto::Channel chl;
  std::unique_ptr<osuCrypto::Session> ep;
  std::unique_ptr<NetIO> io;
  std::unique_ptr<NetIO> io2;
  std::string name = "n";
  VOLEOPRF::PP pp;
  uint64_t comm_send, comm_recv;
  pp = VOLEOPRF::Setup(20);
  std::vector<block> tmp;

  for (auto i = 0; i < 128; i++)
  {
    tmp.emplace_back(Block::MakeBlock(0, i));
  }

  if (context.role == SERVER){
    io = std::make_unique<NetIO>("server", "", 8080);
    io2 = std::make_unique<NetIO>("client", "127.0.0.1", 8081);
    for (auto i = 0; i < 3; i ++)
      ioArr[i] = new sci::NetIO(nullptr, context.port + i + 1);
    ep = std::make_unique<osuCrypto::Session>(ios, context.address, context.port + 4,
                                              osuCrypto::SessionMode::Server, name);
    chl = ep->addChannel(name, name);
    ResetCommunication(sock, chl, ioArr, context);
  }
  else if (context.role == CLIENT){
    io = std::make_unique<NetIO>("client", "127.0.0.1", 8080);
    io2 = std::make_unique<NetIO>("server", "", 8081);
    for (auto i = 0; i < 3; i ++)
      ioArr[i] = new sci::NetIO(context.address.c_str(), context.port + i + 1);
    ep = std::make_unique<osuCrypto::Session>(ios, context.address, context.port + 4,
                                              osuCrypto::SessionMode::Client, name);
    chl = ep->addChannel(name, name);
    ResetCommunication(sock, chl, ioArr, context);
  }
  else {
    throw std::runtime_error("Unsupported role for cycle4 PSI");
  }

  const bool profile_enabled = options.profile || options.profile_candidate_detail;
  std::unique_ptr<Profiler> profiler;
  std::unique_ptr<ProfileScope> protocol_profile_scope;
  if (profile_enabled)
  {
    profiler = std::make_unique<Profiler>(context.role, options.name, x_value,
                                          options.profile_candidate_detail,
                                          io.get(), io2.get(), ioArr,
                                          sock.get(), &chl);
    protocol_profile_scope = std::make_unique<ProfileScope>(profiler.get(), "protocol_total");
  }

  block total_2ans_share = Block::zero_block;

  for (auto i = 0; i < NUM_VERTEX; i ++){ // NUM_VERTEX
      block b_share = Block::zero_block;
      if (i == x_value) continue;
      if (context.role == SERVER){
        ProfileScope profile_scope(profiler.get(), "psi_ca_total", i);
        b_share = psi_ca_sender(set[i], i, context, sock, ioArr, chl, *io, *io2, profiler.get());
      }
      else{
        ProfileScope profile_scope(profiler.get(), "psi_ca_total", i);
        b_share = psi_ca_receiver(set[i], i, context, sock, ioArr, chl, *io, *io2, profiler.get());
      }
      block term_share = Block::zero_block;
      {
        ProfileScope profile_scope(profiler.get(), "beaver_square", i);
        auto triple = generate_beaver_triples_128(context.role, *io2, 1);
        block bb_share = beaver_mul_share_128(b_share, b_share, triple, 0, context.role, *io2);
        term_share = sub_with_borrow(bb_share, b_share);
        total_2ans_share = add_with_carry(total_2ans_share, term_share);
      }
    
      {
        ProfileScope profile_scope(profiler.get(), "term_exchange", i);
        if (context.role == SERVER){
          io2->SendBlock(term_share);
        }
        else{
          block total_share = Block::zero_block;
          io2->ReceiveBlock(total_share);
          block final_ans = add_with_carry(term_share, total_share);
          std::cout << "The local 4cycle counting for vetex " << i << " is " << ((uint64_t *)(&final_ans))[0] << std::endl;
        }
      }

  }
  
  {
    ProfileScope profile_scope(profiler.get(), "final_total_exchange");
    if (context.role == SERVER){
      io2->SendBlock(total_2ans_share);
    }
    else{
      block total_share = Block::zero_block;
      io2->ReceiveBlock(total_share);
      block final_ans = add_with_carry(total_2ans_share, total_share);
      std::cout << "The local 4cycle counting is " << ((uint64_t *)(&final_ans))[0]/2 << std::endl;
    }
  }

  if (protocol_profile_scope)
  {
    protocol_profile_scope.reset();
  }
  if (profiler)
  {
    if (context.role == CLIENT)
      std::this_thread::sleep_for(std::chrono::seconds(2));
    profiler->Print();
  }


  // if (context.role == SERVER)
  // {
  //   NetIO io("server", "", 8080);
  //   NetIO io2("client", "127.0.0.1", 8081);
  //   send_test();
  //   ioArr[0] = new sci::NetIO(nullptr, context.port + 1);
  //   ioArr[1] = new sci::NetIO(nullptr, context.port + 2);
  //   ioArr[2] = new sci::NetIO(nullptr, context.port + 3);
  //   ep = new osuCrypto::Session(ios, context.address, context.port + 4,
  //                               osuCrypto::SessionMode::Server, name);
  //   chl = ep->addChannel(name, name);
  //   ResetCommunication(sock, chl, ioArr, context);
  //   psi_ca_sender(set[0], neighbors.size() * MAX_DEGREE, context, sock, ioArr, chl, io, io2);
  //   auto comm = io.PrintStats();
  //   auto comm2 = io2.PrintStats();
  //   comm_send += std::get<0>(comm) + std::get<0>(comm2);
  //   comm_recv += std::get<1>(comm) + std::get<1>(comm2);
  // }
  // else
  // {
  //   NetIO io("client", "127.0.0.1", 8080);
  //   NetIO io2("server", "", 8081);
  //   recv_test();
  //   ioArr[0] = new sci::NetIO(context.address.c_str(), context.port + 1);
  //   ioArr[1] = new sci::NetIO(context.address.c_str(), context.port + 2);
  //   ioArr[2] = new sci::NetIO(context.address.c_str(), context.port + 3);
  //   ep = new osuCrypto::Session(ios, context.address, context.port + 4,
  //                               osuCrypto::SessionMode::Client, name);
  //   chl = ep->addChannel(name, name);
  //   ResetCommunication(sock, chl, ioArr, context);

  //   psi_ca_receiver(set[0], context, sock, ioArr, chl, io, io2);
  //   auto comm = io.PrintStats();
  //   auto comm2 = io2.PrintStats();
  //   comm_send += std::get<0>(comm) + std::get<0>(comm2);
  //   comm_recv += std::get<1>(comm) + std::get<1>(comm2);
  // }
  // AccumulateCommunicationPSI(sock, chl, ioArr, context);
  // PrintCommunication(context);

  // auto comm_send_double = (double)(context.sentBytes + comm_send) / ((1.0 * (1ULL << 20)));
  // auto comm_recv_double = (double)(context.recvBytes + comm_recv) / ((1.0 * (1ULL << 20)));
  // std::cout << context.role << ": Total Sent Data (MB): " << comm_send_double << std::endl;
  // std::cout << context.role << ": Total Received Data (MB): " << comm_recv_double << std::endl;
  // // run_eq(inputs, context, sock, ioArr, chl);

  // run_circuit_psi(inputs, context, sock, ioArr, chl);
  // PrintTimings(context);
  // AccumulateCommunicationPSI(sock, chl, ioArr, context);
  // PrintCommunication(context);

  // End Connection

  // printFileContent("res_share_P0.dat");
  // printFileContent("res_share_P1.dat");

  sock->Close();
  chl.close();
  ep->stop();
  ios.stop();

  for (int i = 0; i < 3; i++)
  {
    delete ioArr[i];
  }
}
