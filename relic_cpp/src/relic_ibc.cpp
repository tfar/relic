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

#include "cpp/relic_ibc.h"
#include "cpp/relic_hash.h"

extern "C" {
#include "relic_core.h"
}

namespace relic {
namespace IBC {

SHIBS::User::User(const std::vector<char>& id, relic::bn mpk, relic::bn n, relic::bn key) : id_(id), mpk_(mpk), n_(n), key_(key) {

}

bool SHIBS::User::verify(const std::vector<char>& id, const std::vector<char>& message, const std::vector<std::unique_ptr<type> >& signature) const {
	bool valid = false;

	relic::bn s, t;

	s = *dynamic_cast<relic::bn*>(signature[0].get());
	t = *dynamic_cast<relic::bn*>(signature[1].get());

	// s^e =?= H(ID) * t^(H(t, m)) mod n
	relic::bn left_side = s.mxp(mpk_, n_);
	relic::bn right_side = ((relic::hash_mod_bn(n_, id) * t) % n_)
														.mxp(relic::hash_mod_bn(n_, t, message), n_);

	valid = (left_side == right_side);

	return valid;
}

std::vector<std::unique_ptr<type> > SHIBS::User::sign(const std::vector<char>& message) const {
	std::vector<std::unique_ptr<type> > signature;

	relic::bn f; /* message hash */
	relic::bn s, t; /* signature */

	// generate random number r
	relic::bn r;
	do {
		bn_rand(r, BN_POS, bn_bits(n_));
		bn_mod(r, r, n_);
	} while (bn_is_zero(r));

	// compute t = r ^ e mod n
	t = r.mxp(mpk_, n_);

	// compute f = H(t, m), where H is a one way function
	f = relic::hash_mod_bn(n_, t, message);

	// compute s = s_ID * r ^ f mod n
	s = (key_ * r.mxp(f, n_) % n_);

	// write s, t to the vector
	signature.emplace_back(new bn(s));
	signature.emplace_back(new bn(t));
	return signature;
}

SHIBS::KGC::KGC() : IBS::KGC() {
	initRSA();
}

std::unique_ptr<IBS::User> SHIBS::KGC::generateUser(const std::vector<char>& id) {
	// === SH-IBS: Key Extraction ===
	relic::bn ID_key = relic::hash_mod_bn(n_, id);

	ID_key = ID_key.mxp(msk_, n_);

	std::unique_ptr<IBS::User> user(new SHIBS::User(id, mpk_, n_, ID_key));
	return user;
}

void SHIBS::KGC::initRSA() {
	int bits = BN_BITS;
	relic::bn p, q, r;
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
	n_ = p * q;
	p = p - 1;
	q = q - 1;
	phi_n_ = p * q;

  bn_set_2b(mpk_, 16);
  mpk_ += 1;

  bn_gcd_ext(r, msk_, NULL, mpk_, phi_n_);
  if (bn_sign(msk_) == BN_NEG) {
  	msk_ += phi_n_;
  }

  if (r == 1) {
  	p += 1;
  	q += 1;
  }
}

vBNN_IBS::User::User(const std::vector<char>& id, relic::ec mpk, relic::ec keyR, relic::bn keys) : id_(id), mpk_(mpk), keyR_(keyR), keys_(keys) {
}

bool vBNN_IBS::User::verify(const std::vector<char>& id, const std::vector<char>& message, const std::vector<std::unique_ptr<type> >& signature) const {
	bool valid = false;

	ec R = *dynamic_cast<relic::ec*>(signature[0].get());
	bn z = *dynamic_cast<relic::bn*>(signature[1].get());
	bn h = *dynamic_cast<relic::bn*>(signature[2].get());

	// === Signature Verification ===
	bn n = ec::order();
	bn c = hash_mod_bn(n, id, R);
	ec Z = ec::mul_gen(z) - (R + mpk_ * c) * h;

	valid = (h == hash_mod_bn(n, id, message, R, Z));

	return valid;
}

std::vector<std::unique_ptr<type> > vBNN_IBS::User::sign(const std::vector<char>& message) const {
	std::vector<std::unique_ptr<type> > signature;
	
	bn n = ec::order();
	bn y = bn::random() % n;
	bn h, z;
	ec Y = ec::mul_gen(y);
	h = hash_mod_bn(n, id_, message, keyR_, Y);
	z = (y + h * keys_) % n;

	signature.emplace_back(new ec(keyR_));
	signature.emplace_back(new bn(z));
	signature.emplace_back(new bn(h));
	return signature;
}

vBNN_IBS::KGC::KGC() {
	// === Setup ===
	bn n = ec::order();
	msk_ = bn::nonzero_random() % n;
	P_ = ec::generator();
	mpk_ = P_ * msk_;
}

std::unique_ptr<IBS::User> vBNN_IBS::KGC::generateUser(const std::vector<char>& id) {
	// === Key Extraction ===
	bn n = ec::order();
	bn r = bn::nonzero_random() % n;
	bn ID_key;
	ec keyR = ec::mul_gen(r);
	bn keys = (r + hash_mod_bn(n, id, keyR) * msk_) % n;

	std::unique_ptr<IBS::User> user(new vBNN_IBS::User(id, mpk_, keyR, keys));
	return user;
}

ECCSI::User::User(const std::vector<char>& id, relic::ec KPAK, relic::bn SSK, relic::ec PVT) : id_(id), KPAK_(KPAK), SSK_(SSK), PVT_(PVT) {
	HS_ = hash_mod_bn(ec::order(), ec::generator(), KPAK_, id, PVT_);

	fprintf(stdout, "%p, HS_ = ", this);
	bn_print(HS_);
}

bool ECCSI::User::verify(const std::vector<char>& id, const std::vector<char>& message, const std::vector<std::unique_ptr<type> >& signature) const {
	bool valid = false;

	bn q = ec::order();

	bn r = *dynamic_cast<relic::bn*>(signature[0].get());
	bn s = *dynamic_cast<relic::bn*>(signature[1].get());
	ec PVT = *dynamic_cast<relic::ec*>(signature[2].get());

	bn HS = hash_mod_bn(q, ec::generator(), KPAK_, id, PVT);

	fprintf(stdout, "%p, HS_ = ", this);
	bn_print(HS_);

	bn HE = hash_mod_bn(q, HS, r, message);

	fprintf(stdout, "%p, HE = ", this);
	bn_print(HE);

	ec Y = (PVT * HS) + KPAK_;

	ec J = ((ec::generator() * HE) + (Y * r)) * s;

	bn Jx = J.get_x() % q;

	fprintf(stdout, "%p, Jx = ", this);
	bn_print(Jx);

	valid = (Jx != 0 && (Jx == (r % q)));

	return valid;
}

std::vector<std::unique_ptr<type> > ECCSI::User::sign(const std::vector<char>& message) const {
	std::vector<std::unique_ptr<type> > signature;
	bn q = ec::order();
	bn j;

	ec J;
	bn r;
	bn HE;
	do {
		do {
			j = bn::random() % q;
		} while(j == 0);

		J = ec::generator() * j;

		r = J.get_x();

		HE = hash_mod_bn(q, HS_, r, message);
	} while (((HE + r * SSK_) % q) == 0);

	fprintf(stdout, "%p, HE = ", this);
	bn_print(HE);

	fprintf(stdout, "%p, r = ", this);
	bn_print(r);

	bn s = ((HE + r + SSK_).mul_mod_inv(q) * j) % q;

	signature.emplace_back(new bn(r));
	signature.emplace_back(new bn(s));
	signature.emplace_back(new ec(PVT_));
	return signature;
}

ECCSI::KGC::KGC() {
	// === Setup ===
	KSAK_ = bn::nonzero_random();

	KPAK_ = ec::generator() * KSAK_;
}

std::unique_ptr<IBS::User> ECCSI::KGC::generateUser(const std::vector<char>& id) {
	bn q = ec::order();
	bn HS;
	bn SSK;
	ec PVT;

	do {
		bn v = bn::nonzero_random();
		PVT = ec::generator() * v;
		HS = hash_mod_bn(ec::order(), ec::generator(), KPAK_, id, PVT);
		SSK = (KSAK_ + HS * v) % q;
	} while (bn_is_zero(HS) || bn_is_zero(SSK));

	std::unique_ptr<IBS::User> user(new ECCSI::User(id, KPAK_, SSK, PVT));
	return user;
}

}
}
