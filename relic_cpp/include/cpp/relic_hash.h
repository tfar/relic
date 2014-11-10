/*
 * Copyright (c) 2014 Tobias Markmann
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 **/

#pragma once
 
#include <cassert>

#include <array>
#include <string>
#include <vector>

#include "cpp/relic_bn.h"
#include "cpp/relic_ec.h"

extern "C" {
#include "../relic_md.h"
#include "../relic_util.h"
}

namespace relic {
  // c types
  void concat(std::vector<uint8_t> &r, const char *str);
  void concat(std::vector<uint8_t> &r, const int &i);
  template <size_t ARRAY_SIZE>
  void concat(std::vector<uint8_t> &r,
              const std::array<uint8_t, ARRAY_SIZE> &arr) {
    r.insert(r.end(), arr.begin(), arr.end());
  }

  // c++ types
  void concat(std::vector<uint8_t> &r, const std::string &str);

  // relic types
  void concat(std::vector<uint8_t> &r, const ec &P);
  void concat(std::vector<uint8_t> &r, const bn &n);
  // void concat(std::vector<uint8_t> &r, const gt &t);

  template <typename T, typename... Params>
  void concat(std::vector<uint8_t> &r, const T &t,
              const Params &... parameters) {
    concat(r, t);
    concat(r, parameters...);
  }

  template <typename... Params>
  void hash(std::vector<uint8_t> &r, const Params &... parameters) {
    assert((r.size() <= MD_LEN) && "Result vector size greater than currently "
                                   "set hash function in RELIC!");

    std::array<uint8_t, MD_LEN> msg_hash;
    hash<MD_LEN>(msg_hash, parameters...);
    memcpy(r.data(), msg_hash.data(), r.size());
  }

  template <size_t HASH_SIZE, typename... Params>
  void hash(std::array<uint8_t, HASH_SIZE> &r, const Params &... parameters) {
    std::vector<uint8_t> input;

    // calculate full hash
    std::array<uint8_t, MD_LEN> msg_hash;
    for (int n = 0; n < HASH_SIZE; n += MD_LEN) {
      // concat params
      concat(input, n, parameters...);

      // hash block
      md_map(msg_hash.data(), (unsigned char *)input.data(), input.size());

      // copy disired amount into result memory
      memcpy(r.data() + n, msg_hash.data(),
             HASH_SIZE - n < MD_LEN ? (HASH_SIZE - n) : MD_LEN);
    }
  }

  template <typename... Params>
  void hash_mod(bn_t r, bn_t mod, const Params &... parameters) {
    std::array<uint8_t, MD_LEN> msg_hash;
    hash<MD_LEN>(msg_hash, parameters...);
    int len = msg_hash.size();
    if (8 * len > bn_bits(mod)) {
      len = CEIL(bn_bits(mod), 8);
      bn_read_bin(r, msg_hash.data(), len);
      bn_rsh(r, r, 8 * len - bn_bits(mod));
    } else {
      bn_read_bin(r, msg_hash.data(), len);
    }
    bn_mod(r, r, mod);
  }

  template <typename... Params>
  relic::bn hash_mod_bn(const relic::bn &mod, const Params &... parameters) {
    relic::bn r;
    std::array<uint8_t, MD_LEN> msg_hash;
    hash<MD_LEN>(msg_hash, parameters...);
    int len = msg_hash.size();
    if (8 * len > bn_bits(mod)) {
      len = CEIL(bn_bits(mod), 8);
      bn_read_bin(r, msg_hash.data(), len);
      bn_rsh(r, r, 8 * len - bn_bits(mod));
    } else {
      bn_read_bin(r, msg_hash.data(), len);
    }
    bn_mod(r, r, mod);
    return r;
  }
}
