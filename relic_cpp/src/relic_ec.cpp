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

#include "cpp/relic_ec.h"

extern "C" {
#include "relic_core.h"
}

namespace relic {
  ec::ec() {
    init();
  }

  ec::ec(const ec &other) {
    init();
    ec_copy(P, other.P);
  }

  void ec::init() {
    ec_null(P);
    ec_new(P);
  }

  ec::~ec() {
    ec_free(P);
  }

  ec &ec::operator=(const ec &that) {
    ec_copy(P, that.P);
    return *this;
  }

  bn ec::get_x() const {
    ec tmp;
    bn x;
    ec_norm(tmp, *this);
    ec_get_x(x, tmp.P);
    return x;
  }

  bn ec::order() {
    bn n;
    ec_curve_get_ord(n);
    return n;
  }

  ec ec::random() {
    ec rnd;
    ec_rand(rnd);
    return rnd;
  }

  ec ec::generator() {
    ec gen;
    ec_curve_get_gen(gen);
    return gen;
  }

  // comparison operators
  bool operator==(ec &lhs, const ec &rhs) {
    return ec_cmp(lhs.P, rhs.P) == CMP_EQ;
  }

  bool operator!=(ec &lhs, const ec &rhs) {
    return ec_cmp(lhs.P, rhs.P) != CMP_EQ;
  }

  // arithmetic operators
  ec &operator+=(ec &lhs, const ec &rhs) {
    ec_add(lhs.P, lhs.P, rhs.P);
    return lhs;
  }

  ec operator+(ec lhs, const ec &rhs) {
    lhs += rhs;
    return lhs;
  }

  ec &operator-=(ec &lhs, const ec &rhs) {
    ec_sub(lhs.P, lhs.P, rhs.P);
    return lhs;
  }

  ec operator-(ec lhs, const ec &rhs) {
    lhs -= rhs;
    return lhs;
  }

  ec &operator*=(ec &lhs, const bn &rhs) {
    ec_mul(lhs.P, lhs.P, rhs.n);
    return lhs;
  }

  ec operator*(ec lhs, const bn &rhs) {
    lhs *= rhs;
    return lhs;
  }

  ec operator*(bn lhs, const ec &rhs) {
    ec ret = rhs;
    ret *= lhs;
    return ret;
  }

  ec &operator*=(ec &lhs, const dig_t &rhs) {
    ec_mul_dig(lhs.P, lhs.P, rhs);
    return lhs;
  }

  ec operator*(ec lhs, const dig_t &rhs) {
    lhs *= rhs;
    return lhs;
  }

  ec operator*(dig_t lhs, const ec &rhs) {
    ec ret = rhs;
    ret *= lhs;
    return ret;
  }
}
