/*
 * invationsvc.cpp
 *
 *  Created on: 2. 1. 2020
 *      Author: ondra
 */

#include "invationsvc.h"

#include <couchit/num2str.h>
#include <imtjson/binary.h>
#include <imtjson/string.h>
#include <imtjson/value.h>
#include <openssl/hmac.h>

#include "../shared/stringview.h"
#include "../shared/toString.h"

using json::String;
using json::Value;
using ondra_shared::BinaryView;
using ondra_shared::StrViewA;
InvationSvc::InvationSvc(std::string key):key(key),rnd(std::random_device()()) {
}

std::string InvationSvc::createInvation() {
	auto rval = rnd();
	std::string txt;
	ondra_shared::unsignedToString(rval,[&](char c){txt.push_back(c);},36,9);
	return buildInvationStr(txt.substr(0,9));
}

std::string InvationSvc::buildInvationStr(std::string&& str) const {
	unsigned char digest[256];
	unsigned int digest_len = sizeof(digest);
	HMAC(EVP_sha256(),key.data(), key.length(), reinterpret_cast<const unsigned char *>(str.data()), str.length(), digest,&digest_len);
	unsigned long rval= *reinterpret_cast<const unsigned long *>(digest);
	ondra_shared::unsignedToString(rval,[&](char c){str.push_back(c);},36,6);
	return str.substr(0,15);
}

bool InvationSvc::checkInvation(const std::string_view &str) const {
	std::string want = buildInvationStr(std::string(str.substr(0,9)));
	return str == want;

}
