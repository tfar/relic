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

#include <memory>
#include <vector>

#include "relic_bn.h"

namespace relic {
namespace IBC {
	class IBS {
	public:
		class User {
		public:
			virtual ~User() {}
			virtual bool verify(const std::vector<char>& id, const std::vector<char>& message, const std::vector<char>& signature) const = 0;
			virtual std::vector<char> sign(const std::vector<char>& message) const = 0;
		};

		class KGC {
		public:
			virtual ~KGC() {}
			//virtual std::unique_ptr<User> generateUser(const std::vector<char>& id) = 0;
		};
	};

	class SHIBS {
	public:
		class User : public IBS::User {
		public:
			User();
			virtual ~User() {}
			virtual bool verify(const std::vector<char>& id, const std::vector<char>& message, const std::vector<char>& signature) const;
			virtual std::vector<char> sign(const std::vector<char>& message) const;
		};

		class KGC : public IBS::KGC {
		public:
			KGC();
			virtual ~KGC() {}

			//virtual std::unique_ptr<IBS::User> generateUser(const std::vector<char>& id);

		private:
			void initRSA();		

		private:
			relic::bn n;		/* N */
			relic::bn mpk;		/* master public key */
			relic::bn msk;		/* master secret key */
		};
	};

}
}
