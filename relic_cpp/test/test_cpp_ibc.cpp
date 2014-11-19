//#include <stdio.h>

#include "cpp/relic.h"

#include <string>
#include <algorithm>

extern "C" {
#include "relic.h"
#include "relic_test.h"
}

std::vector<char> vecFromString(const std::string& str) {
  return std::vector<char>(str.data(), str.data() + str.size());
}

int main(void) {
  int code = STS_ERR;

  /* Initialize library with default configuration. */
  if (core_init() != STS_OK) {
    core_clean();
    return 1;
  }

  util_banner("Test of relic C++ IBC implementations\n", 0);

  TEST_ONCE("Test SH-IBS") {
    using namespace std;
    using namespace relic;

    shared_ptr<IBC::IBS::KGC> kgc = make_shared<IBC::SHIBS::KGC>();

    unique_ptr<IBC::IBS::User> userA = kgc->generateUser(vecFromString("UserA"));
    unique_ptr<IBC::IBS::User> userB = kgc->generateUser(vecFromString("UserB"));

    vector<char> someMessageA = vecFromString("Some message A.");
    vector<char> someMessageB = vecFromString("Some message B.");

    std::array<std::vector<unique_ptr<type> >, 4> signatures;

    signatures[0] = userA->sign(someMessageA);
    signatures[1] = userA->sign(someMessageB);
    signatures[2] = userB->sign(someMessageA);
    signatures[3] = userB->sign(someMessageB);

    for (int n = 0; n < signatures.size(); n++) {
      TEST_ASSERT(signatures[n].size() != 0, end);
    }

    for (int n = 0; n < signatures.size(); n++) {
      auto id = n > 1 ? vecFromString("UserB") : vecFromString("UserA");
      auto msg = n % 2 ? someMessageB : someMessageA;
      TEST_ASSERT(userA->verify(id, msg, signatures[n]), end);
    }
  }
  TEST_END;

  TEST_ONCE("Test vBNN-IBS") {
    using namespace std;
    using namespace relic;

    shared_ptr<IBC::IBS::KGC> kgc = make_shared<IBC::vBNN_IBS::KGC>();

    unique_ptr<IBC::IBS::User> userA = kgc->generateUser(vecFromString("UserA"));
    unique_ptr<IBC::IBS::User> userB = kgc->generateUser(vecFromString("UserB"));

    vector<char> someMessageA = vecFromString("Some message A.");
    vector<char> someMessageB = vecFromString("Some message B.");

    std::array<std::vector<unique_ptr<type> >, 4> signatures;

    signatures[0] = userA->sign(someMessageA);
    signatures[1] = userA->sign(someMessageB);
    signatures[2] = userB->sign(someMessageA);
    signatures[3] = userB->sign(someMessageB);

    for (int n = 0; n < signatures.size(); n++) {
      TEST_ASSERT(signatures[n].size() != 0, end);
    }

    for (int n = 0; n < signatures.size(); n++) {
      auto id = n > 1 ? vecFromString("UserB") : vecFromString("UserA");
      auto msg = n % 2 ? someMessageB : someMessageA;
      TEST_ASSERT(userA->verify(id, msg, signatures[n]), end);
    }
  }
  TEST_END;

  TEST_ONCE("Test ECCSI") {
    using namespace std;
    using namespace relic;

    shared_ptr<IBC::IBS::KGC> kgc = make_shared<IBC::ECCSI::KGC>();

    unique_ptr<IBC::IBS::User> userA = kgc->generateUser(vecFromString("UserA"));
    unique_ptr<IBC::IBS::User> userB = kgc->generateUser(vecFromString("UserB"));

    vector<char> someMessageA = vecFromString("Some message A.");
    vector<char> someMessageB = vecFromString("Some message B.");

    std::array<std::vector<unique_ptr<type> >, 4> signatures;

    signatures[0] = userA->sign(someMessageA);
    signatures[1] = userA->sign(someMessageB);
    signatures[2] = userB->sign(someMessageA);
    signatures[3] = userB->sign(someMessageB);

    for (int n = 0; n < signatures.size()-3; n++) {
      TEST_ASSERT(signatures[n].size() != 0, end);
    }

    for (int n = 0; n < signatures.size(); n++) {
      auto id = n > 1 ? vecFromString("UserB") : vecFromString("UserA");
      auto msg = n % 2 ? someMessageB : someMessageA;
      TEST_ASSERT(userA->verify(id, msg, signatures[n]), end);
    }
  }
  TEST_END;


  code = STS_OK;

  util_banner("All tests have passed.\n", 0);
end:
  core_clean();
  return code;
}
