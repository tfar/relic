#include <stdio.h>
#include <string>
#include <algorithm>

#include "cpp/relic.h"

extern "C" {
#include "relic.h"
#include "relic_test.h"
}

int main(void) {
  int code = STS_ERR;

  /* Initialize library with default configuration. */
  if (core_init() != STS_OK) {
    core_clean();
    return 1;
  }

  util_banner("Test of relic C++ binding for BN module:\n", 0);

  TEST_ONCE("Test #1") {
    // === SH-IBS: Initialization ===
    relic::bn p, q, t, n, mpk, r, msk;
    int bits = BN_BITS;
    /* Generate different primes p and q. */
    do {
      bn_gen_prime(p, bits / 2);
      bn_gen_prime(q, bits / 2);
    } while (p == q);

    /* Swap p and q so that p is smaller. */
    if (p < q) {
      std::swap(p, q);
    }

    /* n = pq. */
    n = p * q;
    p = p - 1;
    q = q - 1;
    t = p * q;

    bn_set_2b(mpk, 16);
    mpk += 1;

    bn_gcd_ext(r, msk, NULL, mpk, t);
    if (bn_sign(msk) == BN_NEG) {
      msk += t;
    }

    if (r == 1) {
      p += 1;
      q += 1;
    }

    std::string user = "alice@wonderland.lit";

    // === SH-IBS: Key Extraction ===
    relic::bn ID_key = relic::hash_mod_bn(n, user);
    assert((ID_key == relic::hash_mod_bn(n, user)) && "Equal on bn failing.");

    ID_key = ID_key.mxp(msk, n);

    // === SH-IBS: Signature Generation ===
    std::string message = "Some test message.";
    relic::bn f;

    // signature
    relic::bn s;

    // generate random number r
    do {
      bn_rand(r, BN_POS, bn_bits(n));
      bn_mod(r, r, n);
    } while (bn_is_zero(r));

    // compute t = r ^ e mod n
    t = r.mxp(mpk, n);

    // compute f = H(t, m), where H is a one way function
    f = relic::hash_mod_bn(n, t, message);

    // compute s = s_ID * r ^ f mod n
    s = (ID_key * r.mxp(f, n) % n);

    // === SH-IBS: Signature Verification ===

    // s^e =?= H(ID) * t^(H(t, m)) mod n
    relic::bn left_side = s.mxp(mpk, n);
    relic::bn right_side = ((relic::hash_mod_bn(n, user) * t) % n)
                               .mxp(relic::hash_mod_bn(n, t, message), n);

    assert((left_side == right_side) &&
           "SH-IBS signature verification failed!");
  }
  TEST_END;

  code = STS_OK;

  util_banner("All tests have passed.\n", 0);
end:
  core_clean();
  return code;
}
