/*
 * sendmail.h
 *
 *  Created on: 11. 3. 2020
 *      Author: ondra
 */

#ifndef SRC_MAIN_SENDMAIL_H_
#define SRC_MAIN_SENDMAIL_H_
#include <string>

class SendMail {
public:
	SendMail(const std::string &sendmail_path);

	void send(const std::string &recipient, const std::string &body);

protected:
	std::string sendmail_path;
};

#endif /* SRC_MAIN_SENDMAIL_H_ */
