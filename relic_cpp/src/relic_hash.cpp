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

#include "cpp/relic_hash.h"

#include <cstring>

namespace relic {
  void concat(std::vector<uint8_t> &r, const char *s) {
    int len = strlen(s);
    r.insert(r.end(), s, s + len);
  }

  void concat(std::vector<uint8_t> &r, const int &i) {
    int len = sizeof(int);
    r.insert(r.end(), len, 0);
    memcpy(r.data() + r.size() - len, &i, len);
  }

  void concat(std::vector<uint8_t> &r, const std::string &s) {
    concat(r, s.c_str());
  }

  void concat(std::vector<uint8_t> &r, const std::vector<char> &vec) {
    r.insert(r.end(), vec.data(), vec.data() + vec.size());
  }

  void concat(std::vector<uint8_t> &r, const ec &P) {
    int P_size = -1;
   P_size =  ec_size_bin(P.P, 1); // 0 indicates no point compression, 1 indicates compression

    assert(P_size > 0);
    r.insert(r.end(), P_size, 0);
    ec_write_bin(r.data() + r.size() - P_size, P_size, P.P, 1);
  }

  void concat(std::vector<uint8_t> &r, const bn &n) {
    int n_size = bn_size_bin(n);

    assert(n_size > 0);
    r.insert(r.end(), n_size, 0);
    bn_write_bin(r.data() + r.size() - n_size, n_size, n.n);
  }
}
