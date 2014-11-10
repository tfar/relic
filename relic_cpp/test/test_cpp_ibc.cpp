//#include "cpp/relic.h"

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

  util_banner("Test of relic C++ IBS implementations:\n", 0);

  TEST_ONCE("Test SH-IBS") {

  }
  TEST_END;


  code = STS_OK;

  util_banner("All tests have passed.\n", 0);
end:
  core_clean();
  return code;
}