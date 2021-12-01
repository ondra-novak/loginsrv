/*
 * loginGoogle.cpp
 *
 *  Created on: 27. 3. 2020
 *      Author: ondra
 */

#include <imtjson/parser.h>
#include <imtjson/string.h>
#include <imtjson/value.h>

#include "loginGoogle.h"

using json::String;
using json::Value;




json::String getGoogleAccountId(userver::HttpClient &httpc, const std::string_view &token) {
	String url;
	if (token.substr(0,3) == "eyJ")
		url = String({"https://oauth2.googleapis.com/tokeninfo?id_token=",token});
	else
		url = String({"https://oauth2.googleapis.com/tokeninfo?access_token=",token});
	auto response = httpc.GET(url,{});
	if (response->getStatus() == 200) {
		userver::Stream &s = response->getResponse();
		Value resp = Value::parse([&]{return s.getChar();});
		auto email = resp["email"].getString();
		if (email.empty())  {
			throw std::runtime_error("Token doesn't contain e-mail");
		} else {
			return email;
		}
	} else {
		throw std::runtime_error("Failed to validate token: code "+std::to_string(response->getStatus()));
	}
}

