/*
 * loginGoogle.cpp
 *
 *  Created on: 27. 3. 2020
 *      Author: ondra
 */

#include <imtjson/parser.h>
#include <imtjson/string.h>
#include <imtjson/value.h>
#include <simpleServer/http_client.h>
#include <simpleServer/http_headers.h>

#include "loginGoogle.h"

using json::String;
using json::Value;
using simpleServer::HttpClient;
using simpleServer::newHttpsProvider;
using simpleServer::SendHeaders;




json::String getGoogleAccountId(const json::StrViewA token) {
	HttpClient httpc(StrViewA(), newHttpsProvider());
	String url;
	if (token.startsWith("eyJ"))
		url = String({"https://oauth2.googleapis.com/tokeninfo?id_token=",token});
	else
		url = String({"https://oauth2.googleapis.com/tokeninfo?access_token=",token});
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

