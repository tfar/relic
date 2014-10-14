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

extern "C" {
#include "../relic_bn.h"
}

namespace relic {
  class bn {
  public:
    bn();
    bn(const bn &other);
    bn(const dig_t &digit);
    ~bn();

    bn &operator=(const bn &that);

#if ALLOC == AUTO
    operator const bn_st *() const {
      return &n[0];
    }

    operator bn_st *() {
      return &n[0];
    }
#else
    operator bn_t() const {
      return n;
    }
#endif

    bn mxp(const bn &exponent, const bn &mod);

    static bn random(int bits = BN_BITS);

  private:
    void init();

  public:
    bn_t n;
  };

  // comparison operators
  bool operator==(bn &lhs, const bn &rhs);
  bool operator!=(bn &lhs, const bn &rhs);
  bool operator<(bn &lhs, const bn &rhs);
  bool operator<=(bn &lhs, const bn &rhs);
  bool operator>(bn &lhs, const bn &rhs);
  bool operator>=(bn &lhs, const bn &rhs);

  // arithmetic operators
  bn &operator+=(bn &lhs, const bn &rhs);
  bn &operator-=(bn &lhs, const bn &rhs);
  bn &operator*=(bn &lhs, const bn &rhs);
  bn &operator%=(bn &lhs, const bn &rhs);

  // comparison operators with digits
  bool operator==(bn &lhs, const dig_t &b);
  bool operator!=(bn &lhs, const dig_t &b);
  bool operator<(bn &lhs, const dig_t &b);
  bool operator<=(bn &lhs, const dig_t &b);
  bool operator>(bn &lhs, const dig_t &b);
  bool operator>=(bn &lhs, const dig_t &b);

  // arithmetic operators with digits
  bn &operator+=(bn &lhs, const dig_t &rhs);
  bn &operator-=(bn &lhs, const dig_t &rhs);
  bn &operator*=(bn &lhs, const dig_t &rhs);

  bn operator+(bn lhs, const bn &rhs);
  bn operator-(bn lhs, const bn &rhs);
  bn operator*(bn lhs, const bn &rhs);
  bn operator%(bn lhs, const bn &rhs);

  bn operator+(bn lhs, const dig_t &rhs);
  bn operator-(bn lhs, const dig_t &rhs);
  bn operator*(bn lhs, const dig_t &rhs);
}
