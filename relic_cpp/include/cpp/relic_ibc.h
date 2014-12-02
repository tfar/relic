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
#include "relic_ec.h"

namespace relic {
namespace IBC {
	class IBS {
	public:
		class User {
		public:
			virtual ~User() {}
			virtual bool verify(const std::vector<char>& id, const std::vector<char>& message, const std::vector<std::unique_ptr<type> >& signature) const = 0;
			virtual std::vector<std::unique_ptr<type> > sign(const std::vector<char>& message) const = 0;
		};

		class KGC {
		public:
			virtual ~KGC() {}
			virtual std::unique_ptr<User> generateUser(const std::vector<char>& id) = 0;
		};
	};

	/**
	 *	SH-IBS: Shamir IBS implementation
	 */
	class SHIBS {
	public:
		class User : public IBS::User {
		public:
			User(const std::vector<char>& id, relic::bn mpk, relic::bn n, relic::bn key);
			virtual ~User() {}
			virtual bool verify(const std::vector<char>& id, const std::vector<char>& message, const std::vector<std::unique_ptr<type> >& signature) const;
			virtual std::vector<std::unique_ptr<type> > sign(const std::vector<char>& message) const;

		private:
			std::vector<char> id_;
			relic::bn mpk_; /* master */
			relic::bn n_; /* N */

			relic::bn key_;
		};

		class KGC : public IBS::KGC {
		public:
			KGC();
			virtual ~KGC() {}

			virtual std::unique_ptr<IBS::User> generateUser(const std::vector<char>& id);

		private:
			void initRSA();

		private:
			relic::bn n_;		/* N */
			relic::bn phi_n_;		/* phi(n) */
			relic::bn mpk_;		/* master public key */
			relic::bn msk_;		/* master secret key */
		};
	};

	/**
	 *	vBNN-IBS: vBNN-IBS implementation
	 */
	class vBNN_IBS {
	public:
		class User : public IBS::User {
		public:
			User(const std::vector<char>& id, relic::ec mpk, relic::ec keyR, relic::bn keys);
			virtual ~User() {}
			virtual bool verify(const std::vector<char>& id, const std::vector<char>& message, const std::vector<std::unique_ptr<type> >& signature) const;
			virtual std::vector<std::unique_ptr<type> > sign(const std::vector<char>& message) const;

		private:
			std::vector<char> id_;
			relic::ec mpk_; /* master */

			relic::ec keyR_;	/* ID key */
			relic::bn keys_;	/* ID key */
		};

		class KGC : public IBS::KGC {
		public:
			KGC();
			virtual ~KGC() {}

			virtual std::unique_ptr<IBS::User> generateUser(const std::vector<char>& id);

		private:
			relic::ec P_;				/* generator */
			relic::ec mpk_;			/* master public key */
			relic::bn msk_;			/* master secret key */
		};
	};

	/**
	 *	ECCSI: RFC 6507: Elliptic Curve-Based Certificateless Signatures for Identity-Based Encryption (ECCSI)
	 */
	class ECCSI {
	public:
		class User : public IBS::User {
		public:
			User(const std::vector<char>& id, relic::ec KPAK, relic::bn SSK, relic::ec PVT);
			virtual ~User() {}
			virtual bool verify(const std::vector<char>& id, const std::vector<char>& message, const std::vector<std::unique_ptr<type> >& signature) const;
			virtual std::vector<std::unique_ptr<type> > sign(const std::vector<char>& message) const;

		private:
			std::vector<char> id_;

			relic::ec KPAK_; /* master public key */
			relic::bn SSK_;		/* Secret Signing Key */
			relic::ec PVT_;		/* Public Validation Token */

			relic::bn HS_;		/* cached HS value; needed for every signing operation */
		};

		class KGC : public IBS::KGC {
		public:
			KGC();
			virtual ~KGC() {}

			virtual std::unique_ptr<IBS::User> generateUser(const std::vector<char>& id);

		private:
			relic::ec KPAK_; /* master public key */
			relic::bn KSAK_; /* master secret key */
		};
	};

}
}
