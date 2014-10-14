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
#include "../relic_ec.h"
}

#include "relic_bn.h"

namespace relic {
  class ec {
  public:
    ec();
    ec(const ec &other);
    ~ec();

    ec &operator=(const ec &that);

#if ALLOC == AUTO
    operator const CAT(EC_LOWER, st) * () const {
      return &P[0];
    }

    operator CAT(EC_LOWER, st) * () {
      return &P[0];
    }
#else
    operator ec_t() const {
      return P;
    }
#endif

    static ec random();

  private:
    void init();

  public:
    ec_t P;
  };

  // comparison operators
  bool operator==(ec &lhs, const ec &rhs);
  bool operator!=(ec &lhs, const ec &rhs);

  // arithmetic operators
  ec &operator+=(ec &lhs, const ec &rhs);
  ec operator+(ec lhs, const ec &rhs);
  ec &operator-=(ec &lhs, const ec &rhs);
  ec operator-(ec lhs, const ec &rhs);

  ec &operator*=(ec &lhs, const bn &rhs);
  ec operator*(ec lhs, const bn &rhs);
  ec operator*(bn lhs, const ec &rhs);

  ec &operator*=(ec &lhs, const dig_t &rhs);
  ec operator*(ec lhs, const dig_t &rhs);
  ec operator*(dig_t lhs, const ec &rhs);
}
