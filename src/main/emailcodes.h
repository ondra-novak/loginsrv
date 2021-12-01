/*
 * emailcodes.h
 *
 *  Created on: 13. 4. 2020
 *      Author: ondra
 */

#ifndef SRC_MAIN_EMAILCODES_H_
#define SRC_MAIN_EMAILCODES_H_

#include <couchit/couchDB.h>
#include <memory>
#include <mutex>
#include <random>

class EmailCodes {
public:
	EmailCodes(const std::shared_ptr<couchit::CouchDB> &db);

	unsigned int generateCode(json::String email);
	bool checkCode(json::String email, unsigned int code);

protected:
	std::shared_ptr<couchit::CouchDB> db;
	std::recursive_mutex lock;
	std::default_random_engine rnd;
};

#endif /* SRC_MAIN_EMAILCODES_H_ */
