/*
 * loginTrezor.h
 *
 *  Created on: 1. 5. 2020
 *      Author: ondra
 */

#ifndef SRC_MAIN_LOGINTREZOR_H_
#define SRC_MAIN_LOGINTREZOR_H_

json::String getTrezorAccountId(std::string_view token, std::string_view challenge_prefix);




#endif /* SRC_MAIN_LOGINTREZOR_H_ */
