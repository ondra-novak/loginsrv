/*
 * loginApple.cpp
 *
 *  Created on: 13. 3. 2020
 *      Author: ondra
 */


#include <imtjson/jwt.h>
#include <imtjson/jwtcrypto.h>
#include <imtjson/parser.h>
#include <imtjson/string.h>
#include <imtjson/value.h>
#include <openssl/bn.h>
#include <openssl/ossl_typ.h>
#include <openssl/rsa.h>
#include <simpleServer/http_client.h>
#include <simpleServer/http_headers.h>
#include "loginApple.h"
#include <atomic>
#include <map>
#include <mutex>
#include <string>

using json::String;
using json::Value;
using simpleServer::HttpClient;
using simpleServer::newHttpsProvider;
using simpleServer::SendHeaders;



using KeySet = std::map<std::string, json::PJWTCrypto>;
using KeySetPtr = std::shared_ptr<KeySet>;

struct RSAFree {void operator()(RSA * __ptr) const {RSA_free(__ptr);}};
using RSAObject = std::unique_ptr<RSA, RSAFree>;

#if OPENSSL_VERSION_NUMBER < 0x10100000L
int RSA_set0_key(RSA *r, BIGNUM *n, BIGNUM *e, BIGNUM *d) {
	if (n) r->n = n;
	if (e) r->e = e;
	if (d) r->d = d;
	return 0;
}
#endif


static KeySet loadAppleKeys() {
	HttpClient httpc(StrViewA(), simpleServer::newHttpsProvider());
	auto response = httpc.request("GET","https://appleid.apple.com/auth/keys", simpleServer::SendHeaders());
	int code = response.getStatus();
	KeySet ks;
	if (code / 100 == 2) {
		json::Value data = json::Value::parse(response.getBody());
		for (json::Value k : data["keys"]) {
			auto pubKey = k["n"];
			auto kid = k["kid"];
			auto exp = k["e"];

			auto n = pubKey.getBinary(json::base64url);
			auto e = exp.getBinary(json::base64url);

			RSAObject rsa(RSA_new());
			BIGNUM * bnn = BN_bin2bn(n.data,n.length , NULL);
			BIGNUM * bne = BN_bin2bn(e.data, e.length, NULL);
			RSA_set0_key(rsa.get(),bnn,bne,NULL);

			json::PJWTCrypto jwt = new json::JWTCrypto_RS(rsa.release(), 256);
			ks[kid.getString()] = jwt;

		}
	}
	return ks;
}

static KeySetPtr appleKeySet;
static std::mutex appleKeySetGuard;

json::String getAppleAccountId(const json::StrViewA token) {
	KeySetPtr ks;
	std::unique_lock lk(appleKeySetGuard);
	ks = appleKeySet;
	if (ks == nullptr) {
		ks = KeySetPtr(new KeySet(loadAppleKeys()));
		appleKeySet = ks;
	}
	lk.unlock();

	json::Value hdr = json::parseJWTHdr(token);
	if (hdr["alg"].getString() != "RS256") {
		throw std::runtime_error("JWT token signature not supported");
	}
	std::string kid = hdr["kid"].getString();
	json::PJWTCrypto jwt;
	auto pkiter = ks->find(kid);
	if (pkiter == ks->end()) {
		ks = KeySetPtr(new KeySet(loadAppleKeys()));
		pkiter = ks->find(kid);
		if (pkiter == ks->end()) {
			throw std::runtime_error("JWT token signed by an unknown key");
		}
		lk.lock();
		appleKeySet = ks;
		lk.unlock();
		jwt = pkiter->second;
	} else {
		jwt = pkiter->second;
	}

	json::Value body = json::checkJWTTime(json::parseJWT(token, jwt));
	if (body.hasValue()) {
		if (body["email_verified"].getBool() != true)
			throw std::runtime_error("Apple login: Need verified e-mail");
		return body["email"].toString();
	} else {
		throw std::runtime_error("JWT token signature is invalid");
	}
}
