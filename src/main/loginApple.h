/*
 * loginApple.h
 *
 *  Created on: 13. 3. 2020
 *      Author: ondra
 */

#ifndef SRC_MAIN_LOGINAPPLE_H_
#define SRC_MAIN_LOGINAPPLE_H_
#include <imtjson/string.h>

#include <userver/http_client.h>


json::String getAppleAccountId(userver::HttpClient &httpc, const std::string_view &token);


#endif /* SRC_MAIN_LOGINAPPLE_H_ */
