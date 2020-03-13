/*
 * rpcinterface.h
 *
 *  Created on: 11. 3. 2020
 *      Author: ondra
 */

#ifndef SRC_MAIN_RPCINTERFACE_H_
#define SRC_MAIN_RPCINTERFACE_H_
#include <couchit/couchDB.h>
#include <couchit/memview.h>
#include <imtjson/jwt.h>
#include <imtjson/rpc.h>
#include "sendmail.h"

class RpcInterface {
public:

	struct Config {
		SendMail &sendmail;
		json::PJWTCrypto jwt;
		std::shared_ptr<couchit::CouchDB> db;
		std::shared_ptr<couchit::ChangesDistributor> chdist;


	};

	enum Provider {
		email,
		facebook,
		google,
		token,
		apple
	};



	RpcInterface(const Config &cfg);
	virtual ~RpcInterface();

	void initRPC(json::RpcServer &srv);


	void rpcRequestCode(json::RpcRequest req);
	void rpcVerifyCode(json::RpcRequest req);
	void rpcLogin(json::RpcRequest req);
	void rpcParseToken(json::RpcRequest req);
	void rpcSignup(json::RpcRequest req);
	void initNumIDSvc(std::shared_ptr<couchit::ChangesDistributor> chdist);
	void rpcSetProfileData(json::RpcRequest req);
	void rpcGetProfileData(json::RpcRequest req);
	void rpcSetConsentPPD(json::RpcRequest req);
	void rpcFindUser(json::RpcRequest req);
	void rpcLoginAs(json::RpcRequest req);

	struct SessionInfo {
		bool valid = false;
		bool admin = false;
		json::String uid;
	};

	SessionInfo getSession(json::RpcRequest req, bool setError = true);

protected:
	SendMail &sendmail;
	json::PJWTCrypto jwt;
	std::shared_ptr<couchit::CouchDB> db;

	std::string generateCodeEmail(ondra_shared::StrViewA email, ondra_shared::StrViewA app, int code);

	json::Value loginEmail(json::StrViewA token, json::StrViewA email, json::StrViewA app);
	json::Value loginToken(json::StrViewA token);
	json::Value loginFacebook(json::StrViewA token, json::Value &email);
	json::Value loginApple(json::StrViewA token, json::Value &email);
	json::Value loginGoogle(json::StrViewA token, json::Value &email);


	json::Value findUserByEMail(json::StrViewA email);

	json::Value findUserByID(json::StrViewA email);

	std::pair<json::Value,std::uint64_t> createSession(json::Value userId, json::Value exp, json::Value app, bool admin);
	json::Value createRefreshToken(json::Value userId);
	json::Value createSignupToken(json::Value content);
	json::Value loginByDoc(couchit::Document &&doc, json::StrViewA app, int exp);

private:
	json::Value searchUser(const json::Value &srch);
};

#endif /* SRC_MAIN_RPCINTERFACE_H_ */
