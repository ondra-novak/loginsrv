/*
 * loginGoogle.h
 *
 *  Created on: 27. 3. 2020
 *      Author: ondra
 */

#ifndef SRC_MAIN_LOGINGOOGLE_H_
#define SRC_MAIN_LOGINGOOGLE_H_

#include <userver/http_client.h>


json::String getGoogleAccountId(userver::HttpClient &httpc, const std::string_view &token);

#endif /* SRC_MAIN_LOGINGOOGLE_H_ */
