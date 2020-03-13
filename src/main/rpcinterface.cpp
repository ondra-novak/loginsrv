/*
 * rpcinterface.cpp
 *
 *  Created on: 11. 3. 2020
 *      Author: ondra
 */

#include <couchit/couchDB.h>
#include <couchit/document.h>
#include <couchit/result.h>
#include <imtjson/namedEnum.h>
#include <openssl/hmac.h>
#include <shared/stringview.h>
#include "rpcinterface.h"
#include "loginApple.h"
#include <chrono>
#include <memory>
#include <sstream>

using couchit::CouchDB;
using couchit::Document;
using couchit::Result;
using couchit::Row;
using ondra_shared::StrViewA;
using namespace json;

static json::NamedEnum<RpcInterface::Provider> strProvider({
	{RpcInterface::email, "email"},
	{RpcInterface::apple, "apple"},
	{RpcInterface::facebook, "facebook"},
	{RpcInterface::google, "google"},
	{RpcInterface::token, "token"}
});

static Value providers_valid_list(json::array,strProvider.begin(), strProvider.end(),[](const auto &x){return Value(String({"'",x.name}));});

static StrViewA userIndex = R"js(
function(doc) {
	if (doc.email) emit(doc.email);
	if (doc.num_id) emit(doc.num_id);
}
)js";

static Value userIndexDDoc = Object
		("_id","_desig/userIndex")
		("language","javascript")
		("views", Object
				("userIndex", Object
						("map", userIndex)));


static couchit::View userIndexView("_design/userIndex/_view/userIndex", couchit::View::update);

RpcInterface::RpcInterface(const Config &cfg):sendmail(cfg.sendmail),jwt(cfg.jwt),db(cfg.db)
{
	db->putDesignDocument(userIndexDDoc);
}

RpcInterface::~RpcInterface() {
	// TODO Auto-generated destructor stub
}

void RpcInterface::initRPC(json::RpcServer &srv) {

	srv.add("Login.requestCode",this,&RpcInterface::rpcRequestCode);
	srv.add("Login.verifyCode",this,&RpcInterface::rpcVerifyCode);
	srv.add("Login.login",this,&RpcInterface::rpcLogin);
	srv.add("Login.signup",this,&RpcInterface::rpcSignup);
	srv.add("Token.parse",this,&RpcInterface::rpcParseToken);
	srv.add("User.setProfileData",this,&RpcInterface::rpcSetProfileData);
	srv.add("User.getProfileData",this,&RpcInterface::rpcGetProfileData);
	srv.add("User.setConsentPPD",this,&RpcInterface::rpcSetConsentPPD);
	srv.add("Admin.findUser",this,&RpcInterface::rpcFindUser);
	srv.add("Admin.loginAs", this,&RpcInterface::rpcLoginAs);
	srv.add("User2.sendCodeToEmail",this,&RpcInterface::rpcRequestCode);


}

static std::pair<int,int> generateCode(StrViewA email, StrViewA app, int offset) {
	auto now = std::chrono::system_clock::now();
	auto minute = std::chrono::duration_cast<std::chrono::minutes>(now.time_since_epoch()).count();
	minute = minute - offset;
	std::ostringstream buff;
	buff << email << ":" << app << ":" << minute;
	std::string msg = buff.str();
	unsigned char reshash[256];
	unsigned int reshash_len = sizeof(reshash);
	HMAC(EVP_sha1(), email.data, email.length,
			reinterpret_cast<const unsigned char *>(msg.data()),
			msg.length(),reshash,&reshash_len);

	return {
		((reshash[2]*65536+reshash[1]*256+reshash[0]) % 90000)+10000,
		minute
	};
}



void RpcInterface::rpcRequestCode(json::RpcRequest req) {
	if (!req.checkArgs({"string","string"}))
		return req.setArgError();
	auto args = req.getArgs();
	StrViewA email = req[0].getString();
	StrViewA app = req[1].getString();
	int code = generateCode(email,app,0).first;
	std::string body = generateCodeEmail(email, app, code);
	try {
		sendmail.send(email, body);
		req.setResult(true);
	} catch (std::exception &e) {
		req.setError(400, e.what());
	}
}

void RpcInterface::rpcVerifyCode(json::RpcRequest req) {
	if (!req.checkArgs({json::Object
		("email","string")
		("app","string")
		("code","integer")
	})) return req.setArgError();

	auto args = req.getArgs();
	StrViewA email = args[0]["email"].getString();
	StrViewA app = args[0]["app"].getString();
	auto code = args[0]["code"].getInt();

	for (int i = 0; i < 15; i++) {
		int c = generateCode(email,app, i).first;
		if (c == code) {
			req.setResult(true);
			return;
		}
	}

	req.setError(405,"Invalid code");

}

std::string RpcInterface::generateCodeEmail(StrViewA email, StrViewA app, int code) {
	std::ostringstream buff;
	buff << "Subject: Login code " << code << std::endl
		 << std::endl
		 << "Login code for " << email << " and app: " << app << " si " << code << std::endl;
	return buff.str();
}

static Value token_rejected ("token_rejected");

void RpcInterface::rpcLogin(json::RpcRequest req) {
	static Value arglist = Value(json::array,{
			Object("provider",providers_valid_list)
				  ("token","string")
				  ("email",{"undefined","string"})
				  ("app",{"string", "undefined"})
				  ("exp",{"integer","undefined"})
	});

	if (!req.checkArgs(arglist)) return req.setArgError();
	Value args = req.getArgs()[0];
	StrViewA token = args["token"].getString();
	Value email = args["email"];
	StrViewA app = args["app"].getValueOrDefault(StrViewA("hf"));
	auto exp = args["exp"].getValueOrDefault(15);
	Provider provider = strProvider[args["provider"].getString()];
	Value userdoc;
	switch (provider) {
	case RpcInterface::email:
		userdoc = loginEmail(token, email.getString(), app);break;
	case RpcInterface::token:
		userdoc = loginToken(token);break;
	case RpcInterface::facebook:
		userdoc = loginFacebook(token, email);break;
	case RpcInterface::apple:
		try {
			email = getAppleAccountId(token);
			userdoc = findUserByEMail(email.getString());
		} catch (std::exception &e) {
			return req.setError(403, e.what());
		}
		break;
	case RpcInterface::google:
		userdoc = loginGoogle(token, email);break;
	}

	if (userdoc == nullptr) {
		return req.setError(404,"Not found", Object("signup_token",createSignupToken(Object
															("email", email)
															("app",app)
															("exp",exp))));
	}
	if (userdoc.isCopyOf(token_rejected)) {
		return req.setError(403,"Invalid credentials");
	}

	setResultAndContext(req,loginByDoc(userdoc, app,  exp));
}

void RpcInterface::initNumIDSvc(std::shared_ptr<couchit::ChangesDistributor> chdist) {
	chdist->addFn([db=this->db](const couchit::ChangeEvent &ev) mutable {

		if (!ev.doc["num_id"].hasValue()) {
			std::size_t lastId = 0;
			auto q = db->createQuery(userIndexView);
			Result res = q.range(0,"").reversedOrder().limit(1).exec();
			if (!res.empty())  {
				Row rw = res[0];
				lastId = rw.value.getUIntLong();
			}
			Document doc(ev.doc);
			doc.set("num_id", lastId+1);
			db->put(doc);
		}
		return true;
	});
}

void RpcInterface::rpcSetProfileData(json::RpcRequest req) {

	if (!req.checkArgs({"string","any"})) return req.setArgError();

	auto ses = getSession(req);
	if (ses.valid) {
		Document doc ( db->get(ses.uid) );
		Value rev = req.getArgs()[0];
		Value content = req.getArgs()[1];
		if (doc.getRevValue() == rev) {
			doc.set("profile", req.getArgs());
			try {
				db->put(doc);
				req.setResult(true);
				return;
			} catch (const couchit::UpdateException &e) {
				if (e.getError(0).isConflict()) return req.setError(409,"Conflict");
				throw;
			}
		} else {
			return req.setError(409,"Conflict");
		}
	}
}

void RpcInterface::rpcGetProfileData(json::RpcRequest req) {
	if (!req.checkArgs({})) return req.setArgError();
	auto ses = getSession(req);
	if (ses.valid) {
		Value doc = db->get(ses.uid);
		req.setResult(Value({doc["_rev"], Object(doc["profile"])}));
	}
}

void RpcInterface::rpcSetConsentPPD(json::RpcRequest req) {
	if (!req.checkArgs(Value(json::array,{"boolean"}))) return req.setArgError();
	bool en = req.getArgs()[0].getBool();
	auto ses = getSession(req);
	if (ses.valid) {
		for(;;) {
			Document doc = db->get(ses.uid);
			doc.set("cppd", en);
			try {
				db->put(doc);
				return req.setResult(true);
			} catch (const couchit::UpdateException &e) {
				if (!e.getError(0).isConflict()) throw;
			}
		}
	}
}

void RpcInterface::setResultAndContext(json::RpcRequest req, json::Value loginData) {
	Value context = Object("session", loginData["session"]);
	req.setResult(loginData, context);
}

Value RpcInterface::searchUser(const Value &srch) {
	Value doc;
	if (srch.type() == json::string) {
		doc = db->get(srch.getString(), CouchDB::flgNullIfMissing);
	}
	if (!doc.hasValue()) {
		auto q = db->createQuery(userIndexView);
		Result res = q.includeDocs().key(srch).exec();
		if (!res.empty()) {
			Row rw = res[0];
			doc = rw.doc;
		}
	}
	return doc;
}

void RpcInterface::rpcFindUser(json::RpcRequest req) {
	if (!req.checkArgs(Value(json::array,{{"string","number"}}))) return req.setArgError();
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.admin) {
			Value srch = req.getArgs()[0];
			Value doc = searchUser(srch);
			if (doc.hasValue()) {
				req.setResult(doc);
			} else {
				req.setError(404,"Not found");
			}
		} else {
			req.setError(403,"Need to be admin");
		}
	}
}

RpcInterface::SessionInfo RpcInterface::getSession(json::RpcRequest req, bool setError) {
	Value ctx = req.getContext();
	Value ses = ctx["session"];
	if (ses.hasValue()) {
		Value sesInfo = checkJWTTime(parseJWT(ses.getString(), jwt));
		if (sesInfo.hasValue()) {
			if (sesInfo["sub"].getString() == "ses") {
				bool admin = sesInfo["adm"].getBool();
				json::String id = sesInfo["id"].toString();
				return {
					true,
					admin,
					id
				};

			}
		}
	}
	if (setError) {
		req.setError(401,"Unauthorized. Valid session required");
	}
	return {};

}

void RpcInterface::rpcLoginAs(json::RpcRequest req) {
	if (!req.checkArgs(Value(json::array,{{"string","number"},"string",{"number","undefined"}}))) return req.setArgError();
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.admin) {
			Value doc = searchUser(req.getArgs()[0]);
			Value app = req.getArgs()[1];
			auto exp = req.getArgs()[2].getValueOrDefault(15);
			req.setResult(loginByDoc(doc, app.getString(), exp));
		} else {
			req.setError(403,"Need to be admin");
		}
	}

}

json::Value RpcInterface::loginByDoc(couchit::Document &&doc, StrViewA app, int exp) {
	{
		auto lastLogin = doc.object("lastLogin");
		lastLogin.set(app,std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
	}

	db->put(doc);
	auto sesinfo = createSession(doc.getID(), exp, app, doc["admin"].getBool());
	Value rfrtoken = createRefreshToken(doc.getID());
	return (Object
			("session", sesinfo.first)
			("expiration", sesinfo.second)
			("refresh", rfrtoken)
			("num_id", doc["num_id"])
			("profile", doc["profile"])
			("cppd", doc["cppd"])
			("config", json::object),
			Object("session", sesinfo.first)
	);

}


json::Value RpcInterface::loginEmail(json::StrViewA token, json::StrViewA email, json::StrViewA app) {
	int v = std::atoi(token.data);
	for (int i = 0; i < 15; i++) {
		auto cv = generateCode(email,app, i);
		if (cv.first == v) {
			Value doc = findUserByEMail(email);
			if (doc == nullptr) return doc;
			Value lastTOTP = doc["lastTOTP"];
			if (!lastTOTP.defined() || cv.second > lastTOTP.getInt()) {
				doc = doc.replace("lastTOTP",cv.second);
				return doc;
			}
		}
	}
	return token_rejected;
}

json::Value RpcInterface::loginToken(json::StrViewA token) {
	Value pt = parseJWT(token,jwt);
	if (pt.hasValue() && checkJWTTime(pt).hasValue()) {
		Value sub = pt["sub"];
		if (sub.getString() == "rfr") {
			Value id = pt["id"];
			if (id.type() == json::string) {
				Value doc = findUserByID(id.getString());
				Value iat = pt["iat"];
				if (iat.getUIntLong() > doc["tokenRevokeTime"].getUIntLong()) {
					return doc;
				}
			}
		}
	}
	return token_rejected;
}

json::Value RpcInterface::loginFacebook(json::StrViewA token, json::Value &email) {
	return token_rejected;
}

json::Value RpcInterface::loginGoogle(json::StrViewA token, json::Value &email) {
	return token_rejected;
}

json::Value RpcInterface::findUserByEMail(StrViewA email) {
	auto q = db->createQuery(userIndexView);
	Result res = q.includeDocs().key(email).exec();
	if (res.empty()) {
		return nullptr;
	}
	else {
		Row rw = res[0];
		return rw.doc;
	}
}

json::Value RpcInterface::findUserByID(StrViewA id) {
	return db->get(id, CouchDB::flgNullIfMissing);
}

std::pair<json::Value,std::uint64_t> RpcInterface::createSession(json::Value userId, json::Value exp, json::Value app, bool admin) {
	auto expInterval = exp.getUInt();
	if (expInterval == 0 || expInterval > 30) expInterval = 30;
	auto tp = std::chrono::system_clock::now();
	auto e = tp + std::chrono::minutes(exp.getUInt());
	Object payload;
	payload.set("id", userId)
			   ("iat", std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count())
			   ("exp", std::chrono::duration_cast<std::chrono::seconds>(e.time_since_epoch()).count())
			   ("adm", admin)
			   ("sub", "ses")
			   ("app", app);
	std::string token = serializeJWT(payload, jwt);
	return {
		token, std::chrono::duration_cast<std::chrono::milliseconds>(e.time_since_epoch()).count()
	};

}


void RpcInterface::rpcParseToken(json::RpcRequest req) {
	if (!req.checkArgs(Value(json::array,{"string"}))) return req.setArgError();

	Value args = req.getArgs();
	StrViewA t = args[0].getString();

	Value parsed = parseJWT(t,jwt);
	bool valid = true;
	if (!parsed.hasValue()) {
		valid = false;
		parsed = parseJWT(t,nullptr);
	}
	req.setResult(Object
			("signature_valid",valid)
			("time_valid", checkJWTTime(parsed).hasValue())
			("content", parsed));

}

void RpcInterface::rpcSignup(json::RpcRequest req) {
	static Value arglist = {"string",{"boolean","undefined"}};
	if (!req.checkArgs(arglist)) return req.setArgError();
	Value token = parseJWT(req.getArgs()[0].getString(), jwt);
	if (!token.hasValue()) return req.setError(401,"Token is not valid");
	Value content = token["content"];
	StrViewA email = content["email"].getString();
	StrViewA app = content["app"].getString();
	auto exp = content["exp"].getUInt();

	Value trydoc = findUserByEMail(email);
	if (trydoc.hasValue()) {
		req.setResult(loginByDoc(trydoc, app, exp));
	} else {
		Document doc = db->newDocument();
		doc.set("email", email);
		doc.set("first_app", app);
		doc.set("cppd", req.getArgs()[1].getBool());
		setResultAndContext(req,loginByDoc(trydoc, app, exp));
	}


}

json::Value RpcInterface::createRefreshToken(json::Value userId) {
	auto tp = std::chrono::system_clock::now();
	auto e = tp + std::chrono::hours(24*365*2);
	Object payload;
	payload.set("id", userId)
			   ("iat", std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count())
			   ("exp", std::chrono::duration_cast<std::chrono::seconds>(e.time_since_epoch()).count())
			   ("sub", "rfr");
	return serializeJWT(payload, jwt);
}

json::Value RpcInterface::createSignupToken(json::Value content) {
	auto tp = std::chrono::system_clock::now();
	auto e = tp + std::chrono::hours(1);
	Object payload;
	payload.set("content", content)
			   ("iat", std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count())
			   ("exp", std::chrono::duration_cast<std::chrono::seconds>(e.time_since_epoch()).count())
			   ("sub", "sgnup");
	return serializeJWT(payload, jwt);
}
