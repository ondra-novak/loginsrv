/*
 * loginFacebook.cpp
 *
 *  Created on: 27. 3. 2020
 *      Author: ondra
 */


#include <imtjson/string.h>
#include <imtjson/value.h>
#include <shared/stringview.h>
#include "loginFacebook.h"
#include <imtjson/parser.h>

using json::Parser;
using json::String;
using json::Value;


json::String getFacebookAccountId(userver::HttpClient &httpc, const std::string_view &token) {
	String url({"https://graph.facebook.com/me?access_token=",token,"&fields=email"});
	auto resp = httpc.GET(url.str(), {});;
	if (resp->getStatus() == 200) {
		userver::Stream &s = resp->getResponse();
		Value resp = Value::parse([&]{return s.getChar();});
		json::String email = resp["email"].toString();
		if (email.empty())  {
			if (!resp["id"].defined()) throw std::runtime_error("Malformed facebook response");
			email = json::String {resp["id"].toString(),"@facebook"};
		}
		return email;
	} else {
		throw std::runtime_error("Failed to validate token: code "+std::to_string(resp->getStatus()));
	}
}
