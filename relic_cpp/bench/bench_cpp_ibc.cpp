/*
 * RELIC is an Efficient LIbrary for Cryptography
 * Copyright (C) 2007-2014 RELIC Authors
 *
 * This file is part of RELIC. RELIC is legal property of its developers,
 * whose names are not listed here. Please refer to the COPYRIGHT file
 * for contact information.
 *
 * RELIC is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * RELIC is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with RELIC. If not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file
 *
 * Benchmarks for ID-based cryptography algorithms using RELIC C++ binding.
 *
 * @version $Id$
 * @ingroup bench
 */

#include <stdio.h>

#include "cpp/relic.h"

extern "C" {
#include "relic.h"
#include "relic_bench.h"
}

#include <vector>
#include <tuple>

static void bench_shibs() {
  using namespace std;
  using namespace relic;

  IBC::SHIBS::KGC kgc;

  vector<char> idA(50);
  vector<char> idB(50);

  // benchmark key extraction
  rand_bytes((uint8_t*)idA.data(), idA.size());
  IBC::SHIBS::User userA = kgc.generateUser(idA);
  IBC::SHIBS::User userB = kgc.generateUser(idB);
  BENCH_BEGIN("SH-IBS (key extraction)") {
    rand_bytes((uint8_t*)idB.data(), idB.size());
    BENCH_ADD(userB = kgc.generateUser(idB));
  }
  BENCH_END;

  vector<vector<char> > messages;
  for (int n = 0; n < 100; n++) {
    messages.push_back(vector<char>(100));
    rand_bytes((uint8_t*)messages[n].data(), messages[n].size());
  }

  vector<tuple<relic::bn, relic::bn> > signaturesOfA;
  vector<tuple<relic::bn, relic::bn> > signaturesOfB;

  int n = 0;
  for (int n = 0; n < 100; n++) {
    signaturesOfA.push_back(userA.sign(messages[n]));
    signaturesOfB.push_back(userB.sign(messages[n]));
  }
  // benchmark signature generation
  BENCH_BEGIN("SH-IBS (signature generation)") {
    n++;
    BENCH_ADD(signaturesOfA[n % 100] = move(userA.sign(messages[n % 100])));
  }
  BENCH_END;

  // benchmark signature verification
  BENCH_BEGIN("SH-IBS (signature verification)") {
    n++;
    BENCH_ADD(userB.verify(idA, messages[n % 100], signaturesOfA[n % 100]));
  }
  BENCH_END;
}

static void bench_vbnnibs() {
  using namespace std;
  using namespace relic;

  IBC::vBNN_IBS::KGC kgc;

  vector<char> idA(50);
  vector<char> idB(50);

  // benchmark key extraction
  rand_bytes((uint8_t*)idA.data(), idA.size());
  IBC::vBNN_IBS::User userA = kgc.generateUser(idA);
  IBC::vBNN_IBS::User userB = kgc.generateUser(idB);
  
  BENCH_BEGIN("vBNN-IBS (key extraction)") {
    rand_bytes((uint8_t*)idB.data(), idB.size());
    BENCH_ADD(userB = kgc.generateUser(idB));
  }
  BENCH_END;

  vector<vector<char> > messages;
  for (int n = 0; n < 100; n++) {
    messages.push_back(vector<char>(100));
    rand_bytes((uint8_t*)messages[n].data(), messages[n].size());
  }

  vector<tuple<ec, bn, bn> > signaturesOfA;
  vector<tuple<ec, bn, bn> > signaturesOfB;

  int n = 0;
  for (int n = 0; n < 100; n++) {
    signaturesOfA.push_back(userA.sign(messages[n]));
    signaturesOfB.push_back(userB.sign(messages[n]));
  }
  
  // benchmark signature generation
  BENCH_BEGIN("vBNN-IBS (signature generation)") {
    n++;
    BENCH_ADD(signaturesOfA[n % 100] = userA.sign(messages[n % 100]));
  }
  BENCH_END;

  // benchmark signature verification
  BENCH_BEGIN("vBNN-IBS (signature verification)") {
    n++;
    BENCH_ADD(userB.verify(idA, messages[n % 100], signaturesOfA[n % 100]));
  }
  BENCH_END;
}

int main(void) {
  if (core_init() != STS_OK) {
    core_clean();
    return 1;
  }

  assert(ec_param_set_any() == STS_OK);

  conf_print();

  util_banner("Benchmarks for the RELIC C++ IBC implementation:", 0);

  bench_shibs();

  bench_vbnnibs();

  core_clean();
  return 0;
}
