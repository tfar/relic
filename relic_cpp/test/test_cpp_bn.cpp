//#include <stdio.h>

#include "cpp/relic.h"

#include <string>
#include <algorithm>

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

  util_banner("Test of relic C++ IBC implementations\n", 0);

  TEST_ONCE("Test bn::mul_mod_inv") {
    using namespace std;
    using namespace relic;

    bn A = bn::nonzero_random();
    bn q = bn::nonzero_random();

    A = A % q;
    bn A_inv = A.mul_mod_inv(q);

    bn isOne = (A * A_inv) % q;

    TEST_ASSERT(isOne == 1, end);
  }
  TEST_END;

  code = STS_OK;

  util_banner("All tests have passed.\n", 0);
end:
  core_clean();
  return code;
}
