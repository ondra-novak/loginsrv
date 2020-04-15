/*
 * invationsvc.h
 *
 *  Created on: 2. 1. 2020
 *      Author: ondra
 */

#ifndef SRC_MAIN_INVATIONSVC_H_
#define SRC_MAIN_INVATIONSVC_H_
#include <random>
#include <string>
#include "../shared/stringview.h"

class InvationSvc {
public:
	InvationSvc(std::string key);
	std::string createInvation();
	bool checkInvation(const std::string_view &str) const;

protected:
	std::string key;
	std::mt19937_64 rnd;

	std::string buildInvationStr(std::string&& str) const;
};

#endif /* SRC_MAIN_INVATIONSVC_H_ */
