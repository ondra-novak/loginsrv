/*
 * sendmail.cpp
 *
 *  Created on: 11. 3. 2020
 *      Author: ondra
 */

#include <regex>
#include "sendmail.h"

SendMail::SendMail(const std::string &sendmail_path):sendmail_path(sendmail_path) {

}


bool is_email_valid(const std::string& email)
{
   const std::regex pattern ("[-a-zA-Z0-9.+]+@[a-z0-9A-Z-_]+(\.[a-z0-9A-Z-_]+)+");
   return std::regex_match(email, pattern);
}


void SendMail::send(const std::string &recipient, const std::string &body) {
	if (!is_email_valid(recipient)) throw std::runtime_error("Recipient rejected: "+ recipient);
	std::string cmd = sendmail_path+" "+recipient;
	FILE *f = popen(cmd.c_str(),"w");
	if (f == nullptr) throw std::runtime_error("Can't connect sendmail: " + cmd);
	if (fwrite(body.data(), body.size(), 1, f) != 1) {
		pclose(f);
		throw std::runtime_error("Failed to write body: " + cmd);
	}
	int res = pclose(f);
	if (res)
		throw std::runtime_error("Sendmail returned non-zero exit: " + cmd+ " - exit:" + std::to_string(res));
}
