/*
 * rpcinterface.h
 *
 *  Created on: 11. 3. 2020
 *      Author: ondra
 */

#ifndef SRC_MAIN_RPCINTERFACE_H_
#define SRC_MAIN_RPCINTERFACE_H_
#include <couchit/couchDB.h>
#include <couchit/doccache.h>
#include <couchit/memview.h>
#include <imtjson/jwt.h>
#include <imtjson/namedEnum.h>
#include <imtjson/rpc.h>
#include <main/emailcodes.h>
#include "sendmail.h"

class InvationSvc;

class RpcInterface {
public:

	using SpecAccView = couchit::MemView;

	struct Config {
		SendMail &sendmail;
		json::PJWTCrypto jwt;
		std::shared_ptr<couchit::CouchDB> db;
		couchit::ChangesDistributor &chdist;
		couchit::MemView &specAcc;
		InvationSvc *invationSvc;
	};

	enum Provider {
		email,
		facebook,
		google,
		token,
		apple,
		trezor
	};



	RpcInterface(const Config &cfg);
	virtual ~RpcInterface();

	virtual void initRPC(json::RpcServer &srv);


	void rpcRequestCode(json::RpcRequest req);
	void rpcVerifyCode(json::RpcRequest req);
	void rpcLogin(json::RpcRequest req);
	void rpcParseToken(json::RpcRequest req);
	void rpcSignup(json::RpcRequest req);
	void initNumIDSvc(couchit::ChangesDistributor &chdist);
	void rpcSetProfileData(json::RpcRequest req);
	void rpcGetProfileData(json::RpcRequest req);
	void rpcSetConsentPPD(json::RpcRequest req);
	void rpcFindUser(json::RpcRequest req);
	void rpcLoginAs(json::RpcRequest req);

	void rpcLogoutAll(json::RpcRequest req);
	void rpcUserWhoami(json::RpcRequest req);
	void rpcSetRoles(json::RpcRequest req);
	void rpcUserDelete(json::RpcRequest req);
	void rpcAdminDeleteUser(json::RpcRequest req);
	void rpcAdminCreateApp(json::RpcRequest req);
	void rpcAdminGet(json::RpcRequest req);
	void rpcAdminPut(json::RpcRequest req);
	void rpcAdminDelete(json::RpcRequest req);
	void rpcAdminList(json::RpcRequest req);
	void rpcAdminAppList(json::RpcRequest req);
	void rpcSetUserEndpoints(json::RpcRequest req);
	void rpcGetUserEndpoints(json::RpcRequest req);
	void rpcGetLastLogin(json::RpcRequest req);
	void rpcAdminGenTokens(json::RpcRequest req);
	void rpcAdminCreateUser(json::RpcRequest req);
	void rpcAddProvider(json::RpcRequest req);

	void rpcUserId2Index(json::RpcRequest req);
	void rpcUserIndex2Id(json::RpcRequest req);


	void rpcCreateInvations(json::RpcRequest req);

	struct SessionInfo {
		bool valid = false;
		bool admin = false;
		json::String uid;
		json::String app;
		json::Value roles;
	};

	SessionInfo getSession(json::RpcRequest req, bool setError = true);

protected:
	SendMail &sendmail;
	json::PJWTCrypto jwt;
	std::shared_ptr<couchit::CouchDB> db;
	std::shared_ptr<couchit::DocCache> dcache;
	EmailCodes emailCodes;
	InvationSvc *invations;
	couchit::MemView &specAcc;

	std::string generateCodeEmail(ondra_shared::StrViewA email, ondra_shared::StrViewA app, int code);

	json::Value loginEmail(json::StrViewA token, json::StrViewA email, bool oldapi);
	json::Value loginToken(json::StrViewA token);


	json::Value findUserByEMail(json::StrViewA email);

	json::Value findUserByID(json::StrViewA email);

	std::pair<json::Value,std::uint64_t> createSession(json::Value userId, json::Value exp, json::Value app, bool admin, json::Value roles);
	json::Value createRefreshToken(json::Value userId, bool temp = false);
	json::Value createSignupToken(json::Value provider, json::Value email, json::Value app);
	json::Value loginByDoc(couchit::Document &&doc, json::StrViewA app, int exp, bool admin, json::Value roles, bool storeLastLogin);

	void setResultAndContext(json::RpcRequest req, json::Value loginData);
	json::Value searchUser(const json::Value &srch);

	json::Value verifyLoginAndFindUser(Provider provider, const json::StrViewA &token,	json::Value &email, bool oldapi, json::StrViewA app);
	void deactivateUser(couchit::Document &&doc);

	json::Value getApp(json::StrViewA appId);
	json::Value findApp(json::StrViewA appId);

	class NumIDGen;

	struct AppInfo {
		bool valid = false;
		json::Value appId;
		json::Value endpoints;
	};

	AppInfo getAppInfo(json::StrViewA appId, json::Value userdoc, bool force);
	AppInfo getAppInfoFromDoc(json::StrViewA appId, json::Value app, json::Value userdoc);

	void sendWelcomeEmail(StrViewA email, StrViewA app);

	static json::NamedEnum<RpcInterface::Provider> strProvider;
	static json::Value providers_valid_list;
	static json::Value token_rejected;

	bool isSpecAccount(json::Value id) const;
	bool checkSpecAccountPwd(json::Value id, StrViewA pwd) const;

private:
	json::Value createUser(const json::Value &email, const json::Value &cppd = json::Value(true),
			const json::Value &provider = json::Value(), const json::Value &app = json::Value(),
			const json::Value &invation = json::Value());
};

#endif /* SRC_MAIN_RPCINTERFACE_H_ */
