/*
 * loginTrezor.cpp
 *
 *  Created on: 1. 5. 2020
 *      Author: ondra
 */


#include <string_view>
#include <imtjson/string.h>
#include <imtjson/jwtcrypto.h>
#include <openssl/sha.h>
#include <shared/logOutput.h>
#include <shared/stringview.h>
#include "loginTrezor.h"
#include <ctime>

using json::String;
using ondra_shared::BinaryView;
using ondra_shared::logDebug;
using ondra_shared::StrViewA;


static std::time_t parseDate(const json::StrViewA date, time_t now) {
	std::tm t;
	localtime_r(&now, &t);
	auto splt1 = date.split(" ");
	StrViewA dpart = splt1();
	StrViewA tpart = splt1();
	auto splt2 = dpart.split("-");
	StrViewA str_y = splt2();
	StrViewA str_m = splt2();
	StrViewA str_d = splt2();
	auto splt3 = tpart.split(":");
	StrViewA str_h = splt3();
	StrViewA str_n = splt3();
	t.tm_min =  std::atoi(str_n.data);
	t.tm_hour =  std::atoi(str_h.data);
	t.tm_mday =  std::atoi(str_d.data);
	t.tm_mon =  std::atoi(str_m.data)-1;
	t.tm_year = std::atoi(str_y.data)-1900;
	return std::mktime(&t)+t.tm_gmtoff;
}

static std::string sha256(const std::string_view &bin) {
	unsigned char buff[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char *>(bin.data()), bin.length(), buff);
	return std::string(reinterpret_cast<const char *>(buff), SHA256_DIGEST_LENGTH);
}

static std::string hex2bin(const std::string_view &hex) {
	auto l = hex.length();
	std::string out;
	out.reserve(l/2);
	for (decltype(l) i = 0; i < l; i+=2) {
		char b1 = hex[i];
		char b2 = hex[i+1];
		unsigned char c = (isdigit(b1)?b1-'0':toupper(b1)-'A'+10)*16+(isdigit(b2)?b2-'0':toupper(b2)-'A'+10);
		out.push_back(c);
	}
	return out;
}

 void numToVarIntString(std::string &appstr, unsigned int val) {
        if (val < 0xfd) {
        	appstr.push_back(val);
        } else if (val <= 0xffff) {
        	appstr.push_back(0xfd);
        	appstr.push_back(val & 0xFF);
        	appstr.push_back(val >> 8);
        } else {
        	throw std::runtime_error("numToVarIntString - unsupported size");
        }
    }


 static const std::string msglead = "Bitcoin Signed Message:\n";

json::String getTrezorAccountId(const json::StrViewA token, const json::StrViewA challenge_prefix) {

	auto splt = token.split("|");
	StrViewA pubKey = splt();
	StrViewA signature = splt();
	StrViewA challenge = splt();
	if (!challenge.startsWith(challenge_prefix)) return String();
	auto dbeg = challenge.indexOf("(", challenge_prefix.length)+1;
	auto dend = challenge.indexOf(")", dbeg);
	StrViewA date = challenge.substr(dbeg, dend-dbeg);
	std::time_t now = std::time(nullptr);
	std::time_t chdate = parseDate(date, now);
	if (std::abs(chdate - now) > 300) return String();

	std::string bpubkey = hex2bin(pubKey);
	std::string bsign = hex2bin(signature);
	std::string msg;
	msg.append(sha256(hex2bin("00000000")));
	msg.append(sha256(challenge));
	std::string wholemsg;
	numToVarIntString(wholemsg, msglead.length());
	wholemsg.append(msglead);
	numToVarIntString(wholemsg, msg.length());
	wholemsg.append(msg);
	auto msghash = sha256(sha256(wholemsg));
	auto sign = json::alg::parseESSign(BinaryView(StrViewA(bsign).substr(1)));
	std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)> key (EC_KEY_new_by_curve_name(NID_secp256k1), &EC_KEY_free);
	EC_KEY *k1 = key.get();
	const unsigned char *tmp = reinterpret_cast<const unsigned char *>(bpubkey.data());
	EC_KEY *k2 = o2i_ECPublicKey(&k1, &tmp, bpubkey.length());
	if (k2 == 0) return String();
	if (k2 != key.get()) key = decltype(key)(k2, &EC_KEY_free);
	int r = ECDSA_do_verify(reinterpret_cast<const unsigned char *>(msghash.data()), msghash.length(), sign.get(), key.get());
	if (r != 1) {
		return String();
	}
	return json::base64url->encodeBinaryValue(BinaryView(StrViewA(sha256(pubKey)))).toString();
}

