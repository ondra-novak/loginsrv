/*
 * loginFacebook.cpp
 *
 *  Created on: 27. 3. 2020
 *      Author: ondra
 */


#include <imtjson/string.h>
#include <simpleServer/http_client.h>
#include <simpleServer/http_headers.h>
#include <imtjson/value.h>
#include <shared/stringview.h>
#include "loginFacebook.h"
#include <imtjson/parser.h>

using json::Parser;
using json::String;
using json::Value;
using simpleServer::HttpClient;
using simpleServer::newHttpsProvider;
using simpleServer::SendHeaders;



json::String getFacebookAccountId(const json::StrViewA token) {
	HttpClient httpc(StrViewA(), newHttpsProvider());
	String url({"https://graph.facebook.com/me?access_token=",token,"&fields=email"});
	auto response = httpc.request("GET",url,SendHeaders());
	if (response.getStatus() == 200) {
		Value resp = Value::parse(response.getBody());
		StrViewA email = resp["email"].getString();
		if (email.empty())  {
			throw std::runtime_error("Token doesn't contain e-mail");
		} else {
			return email;
		}
	} else {
		throw std::runtime_error("Failed to validate token: code "+std::to_string(response.getStatus()));
	}
}
