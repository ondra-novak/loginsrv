/*
 * rpcInterfaceOld.cpp
 *
 *  Created on: 13. 4. 2020
 *      Author: ondra
 */

#include <couchit/document.h>
#include <imtjson/object.h>
#include <imtjson/string.h>
#include <imtjson/value.h>
#include <main/rpcInterfaceOld.h>

using couchit::Document;
using json::Object;
using json::String;
using json::Value;


RpcInterfaceOld::RpcInterfaceOld(const Config &cfg):RpcInterface(cfg) {
}

void RpcInterfaceOld::initRPC(json::RpcServer &srv) {
	srv.add("User2.sendCodeToEmail",this,&RpcInterface::rpcRequestCode);
	srv.add("User2.login",this,&RpcInterfaceOld::rpcUser2login);
	srv.add("User2.create",this,&RpcInterfaceOld::rpcUser2create);
	srv.add("User2.getEndPoints",this,&RpcInterfaceOld::rpcUser2getEndPoints);
	srv.add("User2.createRefreshToken",this,&RpcInterfaceOld::rpcUser2createRefreshToken);
	srv.add("User2.revokeAllSessions",this,&RpcInterfaceOld::rpcLogoutAll);
	srv.add("User2.whoami",this,&RpcInterfaceOld::rpcUser2whoami);
	RpcInterface::initRPC(srv);
}

RpcInterfaceOld::~RpcInterfaceOld() {
	// TODO Auto-generated destructor stub
}

void setStatusError(json::RpcRequest req, int status, const String message) {
	req.setError(Object("status", status)("statusMessage",message));
}


void RpcInterfaceOld::rpcUser2login(json::RpcRequest req) {
	if (!req.checkArgs({"string","string",{"any","undefined"}})) return req.setArgError();
	auto args = req.getArgs();
	auto strp = args[0].getString();
	auto token = args[1].getString();
	auto opts = args[2];
	auto exp = opts["expiration"].getValueOrDefault(15);
	auto app = opts["appId"].getValueOrDefault("hf");
	auto admin = opts["reqLevel"].getValueOrDefault(StrViewA("admin")) == "admin";
	if (strp.empty() || strp[0] != '@') return req.setError(501, "Not implemented");
	strp = strp.substr(1);
	Provider provider = strProvider[strp];
	Value email;

	if (provider == RpcInterface::email) {
		auto nps = token.indexOf(":");
		if (nps == token.npos)
			return setStatusError(req,401, "Invalid e-mail token");
		email = token.substr(nps+1);
		token = token.substr(0,nps);
	}

	auto userdoc = verifyLoginAndFindUser(provider, token, email, true);
	if (userdoc == nullptr) {
		setStatusError(req,404,"User not registered");
	} else if (userdoc.isCopyOf(token_rejected)) {
		setStatusError(req,403,"Invalid credentials");
	} else {
		auto appinfo = getAppInfo(app, userdoc, false);
		if (!appinfo.valid) {
			return setStatusError(req,400,"Unknown application id");
		} else {
			userdoc = userdoc.replace(json::Path::root/"lastLogin"/app, std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
			db->put(userdoc);
			auto session = createSession(userdoc["_id"],exp,app,admin,Value(json::array,{"hf2"}));
			req.setResult(session.first, Object("session",session.first));
		}
	}
}

void RpcInterfaceOld::rpcUser2create(json::RpcRequest req) {
	if (!req.checkArgs({"string","string",{"any","undefined"}})) return req.setArgError();
	auto args = req.getArgs();
	auto strp = args[0].getString();
	auto token = args[1].getString();
	auto opts= args[2];
	auto app = opts["appId"].getValueOrDefault("hf");
	if (strp.empty() || strp[0] != '@') return setStatusError(req,501, "Not implemented");
	strp = strp.substr(1);
	Provider provider = strProvider[strp];
	Value email;

	if (provider == RpcInterface::email) {
		auto nps = token.indexOf(":");
		if (nps == token.npos)
			return setStatusError(req,401, "Invalid e-mail token");
		email = token.substr(nps+1);
		token = token.substr(0,nps);
	}

	auto userdoc = verifyLoginAndFindUser(provider, token, email, true);
	if (userdoc == nullptr) {
		Document doc = db->newDocument("u");
		doc.set("email", email);
		doc.set("cppd", true);
		db->put(doc);
		sendWelcomeEmail(email.getString(), app);
		req.setResult(true);
	} else if (userdoc.isCopyOf(token_rejected)) {
		setStatusError(req,403, "Invalid credentials");
	} else {
		setStatusError(req,409, "Already exists");
	}
}

void RpcInterfaceOld::rpcUser2getEndPoints(json::RpcRequest req) {
	auto ses = getSession(req);
	if (ses.valid) {
		Value userdoc = findUserByID(ses.uid);
		Value app = findApp(ses.app);
		auto appinfo = getAppInfoFromDoc(ses.app,app,userdoc);
		req.setResult(appinfo.endpoints);
	}
}

void RpcInterfaceOld::rpcUser2createRefreshToken(json::RpcRequest req) {
	if (!req.checkArgs(json::array)) return req.setArgError();
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.roles.indexOf("hf2") != ses.roles.npos) {
			req.setResult(createRefreshToken(ses.uid,false));
		} else {
			setStatusError(req,403, "Permission denied");
		}
	}
}

void RpcInterfaceOld::rpcUser2whoami(json::RpcRequest req) {
	if (!req.checkArgs(json::array)) return req.setArgError();
	Value ctx = req.getContext();
	Value ses = ctx["session"];
	if (ses.hasValue()) {
		Value sesInfo = checkJWTTime(parseJWT(ses.getString(), jwt));
		if (sesInfo.hasValue()) {
			Value level = sesInfo["adm"].getBool()?"admin":"user";
			Value doc = findUserByID(sesInfo["id"].getString());
			Value doclevel = doc["admin"].getBool()?"admin":"user";
			auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			req.setResult(Object
					("appId", sesInfo["app"])
					("availableUserLevel", doclevel)
					("effectiveUserLevel", level)
					("email", doc["email"])
					("expires", (sesInfo["exp"].getUInt() - now)/60.0)
					("flags", "validemail")
					("newsletter", "disabled")
					("testerMode", false)
					("userId", doc["num_id"])
					("userLevel", doclevel)
					("userName", doc["email"])
			);
			return;
		}
	}
	req.setError(401, "Invalid session");
}
