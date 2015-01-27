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

  util_banner("Test of relic C++ binding for EC module:\n", 0);

  TEST_ONCE("Test #1") {
    using namespace relic;
    assert(ec_param_set_any() == STS_OK);

    // === Setup ===
    bn n, x;
    ec P, P_0;
    ec_curve_get_ord(n);
    x = bn::random();
    P = ec::random();
    P_0 = P * x;

    // === Key Extraction ===
    std::string user = "alice@wonderland.lit";
    bn r = bn::random(), s;
    ec R = P * r;
    s = (r + hash_mod_bn(n, user, R) * x) % n;

    // === Signature Generation ===
    std::string message = "Art thou not Romeo, and a Montague?";
    bn y = bn::random(), h, z;
    ec Y;
    Y = P * y;
    h = hash_mod_bn(n, user, message, R, Y);
    z = (y + h * s) % n;

    // === Signature Verification ===
    bn c = hash_mod_bn(n, user, R);
    ec Z = (P * z) - (R + P_0 * c) * h;
    assert((h == hash_mod_bn(n, user, message, R, Z)) &&
           "vBNN-IBS verification failed.");
  }
  TEST_END;

  code = STS_OK;

  util_banner("All tests have passed.\n", 0);
end:
  core_clean();
  return code;
}
