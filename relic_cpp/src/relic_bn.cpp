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

#include "cpp/relic_bn.h"

extern "C" {
#include "relic_core.h"
}

namespace relic {
  bn::bn() {
    init();
  }

  bn::bn(const bn &other) {
    init();
    bn_copy(n, other.n);
  }

  bn::bn(const dig_t &digit) {
    init();
    bn_set_dig(n, digit);
  }

  void bn::init() {
    bn_null(n);
    bn_new(n);
  }

  bn::~bn() {
    bn_free(n);
  }

  bn &bn::operator=(const bn &that) {
    bn_copy(n, that.n);
    return *this;
  }

  bn bn::mxp(const bn &exponent, const bn &mod) {
    relic::bn r;
    bn_mxp(r.n, n, exponent.n, mod.n);
    return *this;
  }

  bn bn::random(int bits) {
    bn rnd;
    bn_rand(rnd, BN_POS, bits);
    return rnd;
  }

  bool operator==(bn &lhs, const bn &rhs) {
    return bn_cmp(lhs.n, rhs.n) == CMP_EQ;
  }

  bool operator!=(bn &lhs, const bn &rhs) {
    return bn_cmp(lhs.n, rhs.n) != CMP_EQ;
  }

  bool operator<(bn &lhs, const bn &rhs) {
    return bn_cmp(lhs.n, rhs.n) == CMP_LT;
  }

  bool operator<=(bn &lhs, const bn &rhs) {
    return (lhs < rhs) || (lhs == rhs);
  }

  bool operator>(bn &lhs, const bn &rhs) {
    return bn_cmp(lhs.n, rhs.n) == CMP_GT;
  }

  bool operator>=(bn &lhs, const bn &rhs) {
    return (lhs > rhs) || (lhs == rhs);
  }

  bn &operator+=(bn &lhs, const bn &rhs) {
    bn_add(lhs.n, lhs.n, rhs.n);
    return lhs;
  }

  bn &operator-=(bn &lhs, const bn &rhs) {
    bn_sub(lhs.n, lhs.n, rhs.n);
    return lhs;
  }

  bn &operator*=(bn &lhs, const bn &rhs) {
    bn_mul(lhs.n, lhs.n, rhs.n);
    return lhs;
  }

  bn &operator%=(bn &lhs, const bn &rhs) {
    bn_mod(lhs.n, lhs.n, rhs.n);
    return lhs;
  }

  bn operator+(bn lhs, const bn &rhs) {
    lhs += rhs;
    return lhs;
  }

  bn operator-(bn lhs, const bn &rhs) {
    lhs -= rhs;
    return lhs;
  }

  bn operator*(bn lhs, const bn &rhs) {
    lhs *= rhs;
    return lhs;
  }

  bn operator%(bn lhs, const bn &rhs) {
    lhs %= rhs;
    return lhs;
  }

  bool operator==(bn &lhs, const dig_t &b) {
    return bn_cmp_dig(lhs.n, b) == CMP_EQ;
  }

  bool operator!=(bn &lhs, const dig_t &b) {
    return bn_cmp_dig(lhs.n, b) != CMP_EQ;
  }

  bool operator<(bn &lhs, const dig_t &b) {
    return bn_cmp_dig(lhs.n, b) == CMP_LT;
  }

  bool operator<=(bn &lhs, const dig_t &rhs) {
    return (lhs < rhs) || (lhs == rhs);
  }

  bool operator>(bn &lhs, const dig_t &rhs) {
    return bn_cmp_dig(lhs.n, rhs) == CMP_GT;
  }

  bool operator>=(bn &lhs, const dig_t &rhs) {
    return (lhs > rhs) || (lhs == rhs);
  }

  bn &operator+=(bn &lhs, const dig_t &rhs) {
    bn_add_dig(lhs.n, lhs.n, rhs);
    return lhs;
  }

  bn &operator-=(bn &lhs, const dig_t &rhs) {
    bn_sub_dig(lhs.n, lhs.n, rhs);
    return lhs;
  }

  bn &operator*=(bn &lhs, const dig_t &rhs) {
    bn_mul_dig(lhs.n, lhs.n, rhs);
    return lhs;
  }

  bn operator+(bn lhs, const dig_t &rhs) {
    lhs += rhs;
    return lhs;
  }

  bn operator-(bn lhs, const dig_t &rhs) {
    lhs -= rhs;
    return lhs;
  }

  bn operator*(bn lhs, const dig_t &rhs) {
    lhs *= rhs;
    return lhs;
  }
}
