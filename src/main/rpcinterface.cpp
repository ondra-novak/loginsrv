/*
 * rpcinterface.cpp
 *
 *  Created on: 11. 3. 2020
 *      Author: ondra
 */

#include <couchit/changeset.h>
#include <couchit/couchDB.h>
#include <couchit/document.h>
#include <couchit/result.h>
#include <imtjson/namedEnum.h>
#include <main/invationsvc.h>
#include <main/loginTrezor.h>
#include <openssl/hmac.h>
#include <shared/stringview.h>
#include "rpcinterface.h"
#include "loginApple.h"
#include "loginFacebook.h"
#include "loginGoogle.h"
#include <chrono>
#include <memory>
#include <sstream>

using couchit::CouchDB;
using couchit::Document;
using couchit::Result;
using couchit::Row;
using ondra_shared::StrViewA;
using namespace json;

json::NamedEnum<RpcInterface::Provider> RpcInterface::strProvider({
	{RpcInterface::email, "email"},
	{RpcInterface::apple, "apple"},
	{RpcInterface::facebook, "facebook"},
	{RpcInterface::google, "google"},
	{RpcInterface::token, "token"},
	{RpcInterface::apple, "apple.com"},
	{RpcInterface::facebook, "facebook.com"},
	{RpcInterface::google, "google.com"},
	{RpcInterface::trezor, "trezor"},
});

Value RpcInterface::providers_valid_list(json::array,strProvider.begin(), strProvider.end(),[](const auto &x){return Value(String({"'",x.name}));});

static StrViewA userIndex = R"js(
function(doc) {
	if (doc.email) emit(doc.email.toLowerCase());
	if (doc.num_id) emit(doc.num_id);
	if (doc.providers) {
		for (var i in doc.providers) {
			emit(doc.providers[i].toLowerCase());
		}
	}
}
)js";

static StrViewA invationIndex = R"js(
function(doc) {
	if (doc.invation) emit(doc.invation);
}
)js";

static Value userIndexDDoc = Object
		("_id","_design/userIndex")
		("language","javascript")
		("views", Object
				("userIndex", Object
						("map", userIndex))
				("invationIndex",Object
						("map", invationIndex))
		);

static StrViewA appIndex = R"js(
function(doc){
	if (doc._id.substr(0,4) == "app.") {
		var id = doc.id;
		var bn = doc._id.substr(4);
		var no_cppd_id = doc.no_cppd_id;
		if (bn) emit(bn,null);
		if (id && id != bn)	emit(id,null);
		if (no_cppd_id && no_cppd_id != bn) emit(no_cppd_id,null);
	}
}
)js";

static Value appIndexDDoc = Object
		("_id","_design/appIndex")
		("language","javascript")
		("views", Object
				("appIndex", Object
						("map", appIndex)));

static StrViewA lastLoginIndex = R"js(
function(doc){
	if (doc.lastLogin) {
		for (var x in doc.lastLogin) {
			emit(doc.lastLogin[x], x);
			emit([x,doc.lastLogin[x]], null);
		}
	}
}
)js";

static Value lastLoginDDoc = Object
		("_id","_design/lastLoginIndex")
		("language","javascript")
		("views", Object
				("lastLoginIndex", Object
						("map", lastLoginIndex)));


static couchit::View userIndexView("_design/userIndex/_view/userIndex", couchit::View::update);
static couchit::View appIndexView("_design/appIndex/_view/appIndex", couchit::View::update);
static couchit::View invationView("_design/userIndex/_view/invationIndex", couchit::View::update);
static couchit::View lastLoginView("_design/lastLoginIndex/_view/lastLoginIndex", couchit::View::update);

RpcInterface::RpcInterface(const Config &cfg)
		:sendmail(cfg.sendmail)
		,jwt(cfg.jwt)
		,db(cfg.db)
		,dcache(new couchit::DocCache(*cfg.db,{}))
		,emailCodes(cfg.db)
		,invations(cfg.invationSvc)
		,specAcc(cfg.specAcc)
{
	db->putDesignDocument(userIndexDDoc);
	db->putDesignDocument(appIndexDDoc);
	db->putDesignDocument(lastLoginDDoc);
	cfg.chdist.addFn([dcache=this->dcache](const couchit::ChangeEvent &ev){
		dcache->update(ev);return true;
	});
}

RpcInterface::~RpcInterface() {
	// TODO Auto-generated destructor stub
}

void RpcInterface::initRPC(json::RpcServer &srv) {

	srv.add("Login.requestCode",this,&RpcInterface::rpcRequestCode);
	srv.add("Login.verifyCode",this,&RpcInterface::rpcVerifyCode);
	srv.add("Login.login",this,&RpcInterface::rpcLogin);
	srv.add("Login.signup",this,&RpcInterface::rpcSignup);
	srv.add("Login.logoutAll",this,&RpcInterface::rpcLogoutAll);
	srv.add("Login.addProvider",this,&RpcInterface::rpcAddProvider);
	srv.add("Token.parse",this,&RpcInterface::rpcParseToken);
	srv.add("User.setProfileData",this,&RpcInterface::rpcSetProfileData);
	srv.add("User.getProfileData",this,&RpcInterface::rpcGetProfileData);
	srv.add("User.setConsentPPD",this,&RpcInterface::rpcSetConsentPPD);
	srv.add("User.whoami",this,&RpcInterface::rpcUserWhoami);
	srv.add("User.delete", this, &RpcInterface::rpcUserDelete);
	srv.add("User.id2index", this, &RpcInterface::rpcUserId2Index);
	srv.add("User.index2id", this, &RpcInterface::rpcUserIndex2Id);
	srv.add("Admin.findUser",this,&RpcInterface::rpcFindUser);
	srv.add("Admin.loginAs", this,&RpcInterface::rpcLoginAs);
	srv.add("Admin.setRoles", this,&RpcInterface::rpcSetRoles);
	srv.add("Admin.deactivateUser", this,&RpcInterface::rpcAdminDeleteUser);
	srv.add("Admin.createApp",this,&RpcInterface::rpcAdminCreateApp);
	srv.add("Admin.createUser",this,&RpcInterface::rpcAdminCreateUser);
	srv.add("Admin.get",this,&RpcInterface::rpcAdminGet);
	srv.add("Admin.put",this,&RpcInterface::rpcAdminPut);
	srv.add("Admin.delete",this,&RpcInterface::rpcAdminDelete);
	srv.add("Admin.list",this,&RpcInterface::rpcAdminList);
	srv.add("Admin.appList",this,&RpcInterface::rpcAdminAppList);
	srv.add("Admin.genTokens",this,&RpcInterface::rpcAdminGenTokens);
	srv.add("Admin.setUserEndpoints",this,&RpcInterface::rpcSetUserEndpoints);
	srv.add("Admin.getUserEndpoints",this,&RpcInterface::rpcGetUserEndpoints);
	srv.add("Admin.lastLogin",this,&RpcInterface::rpcGetLastLogin);
	if (invations) {
		srv.add("Admin.createInvations",this,&RpcInterface::rpcCreateInvations);
	}


}



void RpcInterface::rpcRequestCode(json::RpcRequest req) {
	if (!req.checkArgs({"string","string"}))
		return req.setArgError();
	auto args = req.getArgs();
	StrViewA app = req[1].getString();

	if (!isSpecAccount(req[0])) {
		StrViewA email = req[0].getString();
		int code = emailCodes.generateCode(email);
		std::string body = generateCodeEmail(email, app, code);
		try {
			sendmail.send(email, body);
			req.setResult(true);
		} catch (std::exception &e) {
			req.setError(400, e.what());
		}
	} else {
		req.setResult(true);
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
//	StrViewA app = args[0]["app"].getString();
	auto code = args[0]["code"].getInt();
	if (emailCodes.checkCode(email, code, true)) {
		req.setResult(true);
		return;
	} else {
		req.setError(405,"Invalid code");
	}

}


static std::string replace_placeholders(std::string templ, std::string seq, std::string value) {
	std::ostringstream buff;
	auto p = templ.find(seq);
	decltype(p) q = 0;
	while (p != templ.npos) {
		buff << templ.substr(q,p-q);
		buff << value;
		q = p + seq.length();
		p = templ.find(seq,q);
	}
	buff << templ.substr(q);
	return buff.str();
}

std::string RpcInterface::generateCodeEmail(StrViewA email, StrViewA app, int code) {

	String appid ({"app.",app});
	Value appdoc = db->get(appid, db->flgNullIfMissing);
	Value emails = appdoc["emails"];
	Value reqcode = emails["request_code"];
	if (reqcode.hasValue()) {

		return replace_placeholders(reqcode.getString(),"${code}",std::to_string(code));

	} else{
		std::ostringstream buff;
		buff << "Subject: Login code " << code << std::endl
			 << std::endl
			 << "Login code for " << email << " and app: " << app << " si " << code << std::endl;

		return buff.str();
	}

}

void RpcInterface::rpcCreateInvations(json::RpcRequest req) {
	if (!req.checkArgs(Value(json::array,{"number"}))) return req.setArgError();
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.admin) {
			auto count = req.getArgs()[0].getUInt();
			Array res;
			while (count > 0) {
				count--;
				res.push_back(invations->createInvation());
			}
			req.setResult(res);
		} else {
			req.setError(403,"Need to be admin");
		}
	}
}

void RpcInterface::rpcAddProvider(json::RpcRequest req) {
	static Value arglist = {"string"};
	if (!req.checkArgs(arglist)) return req.setArgError();
	Value token = checkJWTTime(parseJWT(req.getArgs()[0].getString(), jwt));
	if (!token.hasValue()) return req.setError(401,"Token is not valid");
	Value email = token["email"];
	Value app = token["app"];
	Value provider = token["provider"];
	if (!provider.hasValue()) return req.setError(401,"Token is not valid");
	auto ses = getSession(req);
	if (ses.valid) {
		Document doc = findUserByID(ses.uid);
		{
			auto providers = doc.object("providers");
			providers.set(provider.getString(), email);
		}
		db->put(doc);
		req.setResult(true);
	}


}

void RpcInterface::rpcAdminCreateUser(json::RpcRequest req) {
	if (!req.checkArgs(Value({"string",{"boolean","undefined"}}))) return req.setArgError();
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.admin) {
			Value email = req.getArgs()[0];
			Value cppd = req.getArgs()[1].getValueOrDefault(Value(true));
			Value doc = createUser(email, cppd);
			req.setResult(doc["_id"]);
		}
	}

}

void RpcInterface::sendWelcomeEmail(StrViewA email, StrViewA app) {

	String appid ({"app.",app});
	Value appdoc = db->get(appid, db->flgNullIfMissing);
	Value emails = appdoc["emails"];
	Value first_login = emails["first_login"];
	if (first_login.hasValue()) {
		try {
			sendmail.send(email, first_login.getString());
		} catch (...) {
			//sending e-mail failure is not reason to reject signup
		}
	}
}


Value RpcInterface::token_rejected ("token_rejected");


Value RpcInterface::verifyLoginAndFindUser(Provider provider, const StrViewA &token, Value &email, bool oldapi, json::StrViewA app) {
	Value userdoc;
	switch (provider) {
	case RpcInterface::email:
		if (isSpecAccount(email)) {
			if (checkSpecAccountPwd(email, token)) {
				userdoc = findUserByEMail(email.getString());
			}  else {
				return token_rejected;
			}
		} else {
			userdoc = loginEmail(token, email.getString(), oldapi);
		}
		break;
	case RpcInterface::token:
		userdoc = loginToken(token);
		break;
	case RpcInterface::facebook:
		email = getFacebookAccountId(token);
		userdoc = findUserByEMail(email.getString());
		break;
	case RpcInterface::apple:
		try {
			email = getAppleAccountId(token);
			userdoc = findUserByEMail(email.getString());
		} catch (std::exception &e) {
			userdoc = token_rejected;
		}
		break;
	case RpcInterface::google:
		email = getGoogleAccountId(token);
		userdoc = findUserByEMail(email.getString());
		break;
	case RpcInterface::trezor: {
		Value appdoc = getApp(app);
		auto z =  getTrezorAccountId(token, appdoc["trezor_challenge"].getString());
		if (z.empty()) return token_rejected;
		email =  z + "@trezor";
		userdoc = findUserByEMail(email.getString());
	}

	}
	return userdoc;
}

void RpcInterface::rpcLogin(json::RpcRequest req) {
	static Value arglist = Value(json::array,{
			Object("provider",providers_valid_list)
				  ("token","string")
				  ("email",{"undefined","string"})
				  ("app",{"string", "undefined"})
				  ("exp",{"integer","undefined"})
				  ("admin",{"boolean","undefined"})
				  ("roles",{{json::array,"string"},"undefined"})
	});

	if (!req.checkArgs(arglist)) return req.setArgError();
	Value args = req.getArgs()[0];
	StrViewA token = args["token"].getString();
	Value email = args["email"];
	Value roles = args["roles"];
	StrViewA app = args["app"].getValueOrDefault(StrViewA("hf"));
	auto exp = args["exp"].getValueOrDefault(15);
	auto admin = args["admin"].getBool();
	Provider provider = strProvider[args["provider"].getString()];
	Value userdoc = verifyLoginAndFindUser(provider, token, email, false, app);
	if (userdoc == nullptr) {
		req.setResult(Object
				("new_user",true)
				("signup_token", createSignupToken(strProvider[provider],email,app)));
	} else if (userdoc.isCopyOf(token_rejected)) {
		req.setError(403, "Invalid credentials");
	} else {
		setResultAndContext(req, loginByDoc(userdoc, app, exp, admin,roles,true));
	}
}

class RpcInterface::NumIDGen: public couchit::IChangeEventObserver {
public:
	NumIDGen(CouchDB &db):db(db) {
		lastIdDoc = db.getLocal("numIdGen", CouchDB::flgCreateNew);
	};
	virtual json::Value getLastKnownSeqID() const;
	virtual bool onEvent(const couchit::ChangeEvent &ev);
	CouchDB &db;
	Document lastIdDoc;
};

json::Value RpcInterface::NumIDGen::getLastKnownSeqID() const {
	return lastIdDoc["lastId"];
}
bool RpcInterface::NumIDGen::onEvent(const couchit::ChangeEvent &ev) {

	if (!ev.doc["num_id"].hasValue() && !ev.deleted && ev.id[0] != '_') {
		std::size_t lastId = 0;
		auto q = db.createQuery(userIndexView);
		Result res = q.range(0,"").reversedOrder().limit(1).exec();
		if (!res.empty())  {
			Row rw = res[0];
			lastId = rw.key.getUIntLong();
		}
		Document doc(ev.doc);
		doc.set("num_id", lastId+1);
		if (lastId == 0) doc.set("admin",true);
		db.put(doc,{true,false,1,true,nullptr});
		lastIdDoc("lastId", ev.seqId);
		db.put(lastIdDoc);
	}
	return true;
}

void RpcInterface::initNumIDSvc(couchit::ChangesDistributor &chdist) {
	chdist.add(std::make_unique<NumIDGen>(*db));
}

void RpcInterface::rpcSetProfileData(json::RpcRequest req) {

	if (!req.checkArgs({"string","any"})) return req.setArgError();

	auto ses = getSession(req);
	if (ses.valid) {
		Document doc ( db->get(ses.uid) );
		Value rev = req.getArgs()[0];
		Value content = req.getArgs()[1];
		if (doc.getRevValue() == rev) {
			doc.set("profile", content);
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
					id,
					sesInfo["app"].toString(),
					sesInfo["rls"]
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
	static Value arglist = {{"string","number"},
					Object("app",{"string", "undefined"})
						  ("exp",{"integer","undefined"})
						  ("admin",{"boolean","undefined"})
						  ("not_local_user",{"boolean","undefined"})
						  ("roles",{{json::array,"string"},"undefined"})};
	if (!req.checkArgs(arglist)) return req.setArgError();
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.admin) {
			Value opts = req.getArgs()[1];
			bool not_local_user = opts["not_local_user"].getBool();
			Value uid = req.getArgs()[0];
			auto app = opts["app"].getValueOrDefault("hf");
			auto exp = opts["exp"].getValueOrDefault(15);
			auto roles = opts["roles"];
			auto admin = opts["admin"].getBool();
			if (not_local_user) {
				auto s = createSession(uid, exp, app,admin,roles);
				req.setResult(Object
							("session", s.first)
							("expiration", s.second));

			} else {
				Value doc = searchUser(uid);
				if (doc.hasValue()) {
					req.setResult(loginByDoc(doc, app, exp, admin, roles,false));
				} else {
					req.setError(404,"Not found");
				}
			}
		} else {
			req.setError(403,"Need to be admin");
		}
	}

}

json::Value filterRoles(const Document &doc, Value roles) {
	Value myr = doc["roles"];
	if (!myr.hasValue() || !roles.hasValue()) return myr;
	return myr.filter([&](Value z){
		return roles.indexOf(z) != roles.npos;
	});
}

json::Value RpcInterface::loginByDoc(couchit::Document &&doc, StrViewA app, int exp, bool admin, Value roles, bool storeLastLogin) {
	roles = filterRoles(doc, roles);
	auto appinfo = getAppInfo(app, doc.getBaseObject(), admin);
	if (!appinfo.valid) throw std::runtime_error("Unknown application id");
	if (storeLastLogin)	{
		{
			auto lastLogin = doc.object("lastLogin");
			lastLogin.set(app,std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
		}
		db->put(doc,{true,false,1,true,nullptr},true);
	}
	bool enable_admin = doc["admin"].getBool() && admin;
	auto sesinfo = createSession(doc.getID(), exp, appinfo.appId.getString(), enable_admin, roles);
	Value rfrtoken = createRefreshToken(doc.getID());
	return Object
			("new_user",false)
			("session", sesinfo.first)
			("expiration", sesinfo.second)
			("refresh", rfrtoken)
			("num_id", doc["num_id"])
			("id", doc.getIDValue())
			("profile", doc["profile"])
			("cppd", doc["cppd"])
			("email", doc["email"])
			("roles", roles)
			("admin", enable_admin)
			("endpoints", appinfo.endpoints);


}


json::Value RpcInterface::loginEmail(json::StrViewA token, json::StrViewA email, bool oldapi) {
	if (token.empty()) return token_rejected;
	int v = std::atoi(token.data);
	if (emailCodes.checkCode(email,v,oldapi)) {
		Value doc = findUserByEMail(email);
		return doc;
	} else {
		return token_rejected;
	}
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

String toLower(String x) {
	auto str = x.wstr();
	std::transform(str.begin(), str.end(), str.begin(), std::towlower);
	return String(StrViewW(str));
}

json::Value RpcInterface::findUserByEMail(StrViewA email) {
	auto q = db->createQuery(userIndexView);
	Result res = q.includeDocs().key(toLower(email)).exec();
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

std::pair<json::Value,std::uint64_t> RpcInterface::createSession(json::Value userId, json::Value exp, json::Value app, bool admin, json::Value roles) {
	auto expInterval = exp.getUInt();
	if (expInterval == 0 || expInterval > 30) expInterval = 30;
	auto tp = std::chrono::system_clock::now();
	auto e = tp + std::chrono::minutes(exp.getUInt());
	Object payload;
	payload.set("id", userId)
			   ("iat", std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count())
			   ("exp", std::chrono::duration_cast<std::chrono::seconds>(e.time_since_epoch()).count())
			   ("adm", admin)
			   ("rls", roles.empty()?Value():roles)
			   ("sub", "ses")
			   ("iss", "adveri")
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

bool RpcInterface::isSpecAccount(json::Value id) const {
	auto cntr = specAcc.direct();
	return cntr.find(id) != cntr.end();
}

bool RpcInterface::checkSpecAccountPwd(json::Value id, StrViewA pwd) const {
	auto cntr = specAcc.direct();
	auto iter = cntr.find(id);
	return iter != cntr.end() && iter->second.value().getString() == pwd;
}

Value RpcInterface::createUser(const Value &email, const Value &cppd,
		const Value &provider, const Value &app, const Value &invation) {
	Value trydoc = findUserByEMail(email.getString());
	if (!trydoc.hasValue()) {
		Document doc = db->newDocument("u");
		doc.set("email", email);
		if (provider.hasValue()) {
			doc.set("providers", Object(provider.getString(), email));
		}
		doc.set("cppd", cppd);
		doc.set("invation", invations ? invation : Value());
		doc.set("createTime",std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
		trydoc = doc;
		db->put(doc,{true,false,1,true,nullptr},false);
		if (app.hasValue()) {
			sendWelcomeEmail(email.getString(), app.getString());
		}
	}
	return trydoc;
}

void RpcInterface::rpcSignup(json::RpcRequest req) {
	static Value arglist = {"string",{"boolean","undefined"},{"string","undefined"}};
	if (!req.checkArgs(arglist)) return req.setArgError();
	Value token = checkJWTTime(parseJWT(req.getArgs()[0].getString(), jwt));
	if (!token.hasValue()) return req.setError(401,"Token is not valid");
	Value email = token["email"];
	Value app = token["app"];
	Value provider = token["provider"];
	Value invation = req.getArgs()[2];
	if (invations) {
		if (!invation.hasValue()) return req.setError(417, "Invation required");
		if (!invations->checkInvation(invation.getString())) return req.setError(418,"Invalid invation code");
		if (!Result(db->createQuery(invationView).key(invation).exec()).empty()) return req.setError(419,"Invation already used");
	}
	Value cppd = req.getArgs()[1].getBool();

	Value trydoc = createUser(email, cppd, provider, app, invation);
	req.setResult(Object
			("token", createRefreshToken(trydoc["_id"],true))
			);


}

json::Value RpcInterface::createRefreshToken(json::Value userId, bool temp) {
	auto tp = std::chrono::system_clock::now();
	auto e = tp + std::chrono::hours(temp?1:24*365*2);
	Object payload;
	payload.set("id", userId)
			   ("iat", std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count())
			   ("exp", std::chrono::duration_cast<std::chrono::seconds>(e.time_since_epoch()).count())
			   ("sub", "rfr")
			   ("iss", "adveri");
	return serializeJWT(payload, jwt);
}


json::Value RpcInterface::createSignupToken(json::Value provider, json::Value email, json::Value app) {
	auto tp = std::chrono::system_clock::now();
	auto e = tp + std::chrono::hours(1);
	Object payload;
	payload.set("email", email)
			   ("app", app)
			   ("provider", provider)
			   ("iat", std::chrono::duration_cast<std::chrono::seconds>(tp.time_since_epoch()).count())
			   ("exp", std::chrono::duration_cast<std::chrono::seconds>(e.time_since_epoch()).count())
			   ("sub", "sgnup");
	return serializeJWT(payload, jwt);
}

void RpcInterface::rpcSetRoles(json::RpcRequest req) {
	static Value arglist = {{"string","number"},
					Object("admin",{"boolean","undefined"})
						  ("roles",{{json::array,"string"},"undefined"})};
	if (!req.checkArgs(arglist)) return req.setArgError();
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.admin) {
			Value user = searchUser(req.getArgs()[0]);
			Value opts = req.getArgs()[1];
			if (user.hasValue()) {
				Document doc(user);
				Value admin = opts["admin"];
				Value roles = opts["roles"];
				if (admin.hasValue()) doc.set("admin", admin);
				if (roles.hasValue()) doc.set("roles", roles);
				db->put(doc);
				req.setResult(doc);
			} else {
				req.setError(404,"Not found");
			}
		} else {
			req.setError(403,"Need to be admin");
		}
	}

}


void RpcInterface::rpcLogoutAll(json::RpcRequest req) {
	if (!req.checkArgs(json::array)) return req.setArgError();
	auto ses = getSession(req);
	if (ses.valid) {
		auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
		Document doc = db->get(ses.uid);
		doc.set("tokenRevokeTime", now);
		db->put(doc);
		req.setResult(true);
	}
}


void RpcInterface::rpcUserWhoami(json::RpcRequest req) {
	if (!req.checkArgs(json::array)) return req.setArgError();
	Value ctx = req.getContext();
	Value ses = ctx["session"];
	if (ses.hasValue()) {
		Value sesInfo = checkJWTTime(parseJWT(ses.getString(), jwt));
		if (sesInfo.hasValue()) {
			Value level = sesInfo["adm"].getBool()?"admin":"user";
			Value doc = findUserByID(sesInfo["id"].getString());
			auto now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
			req.setResult(Object
					("appId", sesInfo["app"])
					("admin", sesInfo["adm"])
					("roles", sesInfo["rls"])
					("id", sesInfo["id"])
					("expires", (sesInfo["exp"].getUInt() - now)/60.0)
					("available_roles", doc["roles"])
					("available_admin", doc["admin"])
					("email", doc["email"])
					("num_id", doc["num_id"])
			);
			return;
		}
	}
	req.setError(401, "Invalid session");
}

void RpcInterface::rpcUserDelete(json::RpcRequest req) {
	if (!req.checkArgs(json::array)) return req.setArgError();
	auto ses = getSession(req);
	if (ses.valid) {
		deactivateUser(findUserByID(ses.uid));
		req.setResult(true);
	}
}

void RpcInterface::rpcAdminDeleteUser(json::RpcRequest req) {
	static Value arglist = {{"string","number"}};
	if (!req.checkArgs(arglist)) return req.setArgError();
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.admin) {
			Value user = findUserByID(req.getArgs()[0].getString());
			if (user.hasValue()) {
				deactivateUser(user);
			} else {
				req.setError(404,"Not found");
			}
		}
	}
}

void RpcInterface::rpcAdminCreateApp(json::RpcRequest req) {
	if (!req.checkArgs({"string"})) return req.setArgError();
	String name = req.getArgs()[0].toString();
	auto iter = std::find_if_not(name.begin(), name.end(), [&](char c) {
		return isalnum(c) || strchr("_-~",c) != nullptr;
	});
	if (iter != name.end()) {
		req.setError(400,"Invalid name");
	} else {
		String id = {"app.",name};
		Value v = db->get(id, CouchDB::flgNullIfMissing);
		if (v != nullptr) {
			req.setError(409,"Already exists");
		}
		req.setResult(Object
				("_id", id)
				("id",name)
				("no_cppd_id",name)
				("endpoints", Object("_default", json::object))
				("emails",Object("request_code","Subject: Your login code id ${code}\r\n\r\nYour login code is ${code}.\r\n")
						        ("first_login","Subject: Welcome user\r\n\r\nWelcome user on the server.\r\n")
				)
		);
	}
}

void RpcInterface::rpcAdminGet(json::RpcRequest req) {
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.admin) {
			Value lst = req.getArgs();
			auto chkitr =  std::find_if_not(lst.begin(), lst.end(), [](Value z){return z.type() == json::string;});
			if (chkitr != lst.end()) {
				return req.setError(400,"Invalid document ID", *chkitr);
			}
			auto q = db->createQuery(couchit::View::includeDocs);
			Result res = q.keys(lst).exec();
			req.setResult(Value(json::object, res.begin(), res.end(),[&](Value z) {
				return Value(z["id"].getString(),z["doc"]);
			}));
		} else {
			req.setError(403,"Need admin");
		}
	}
}

void RpcInterface::rpcAdminPut(json::RpcRequest req) {
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.admin) {

			Array conflicts;
			Object errors;
			Object results;
			auto chset = db->createChangeset();
			for (Value z: req.getArgs()) chset.update(z);
			try {
				chset.commit();
			} catch (const couchit::UpdateException &e) {
				for (std::size_t i = 0, cnt = e.getErrorCnt(); i < cnt; i++) {
					const auto &err = e.getError(i);
					if (err.isConflict()) {
						conflicts.push_back(err.document["_id"]);
					}  else  {
						errors.set(Value(err.document["_id"].getString(), err.errorDetails));
					}
				}
			}
			for (const auto &x:chset.getCommitedDocs()) {
				results.set(x.id, x.newRev);
			}
			req.setResult(Object
					("conflicts", conflicts)
					("errors", errors)
					("commited", results));
		} else {
			req.setError(403,"Need admin");
		}
	}
}

void RpcInterface::rpcAdminDelete(json::RpcRequest req) {
}

void RpcInterface::deactivateUser(couchit::Document &&doc) {
	doc.set("_deleted", true);
	db->put(doc);
}

json::Value RpcInterface::getApp(json::StrViewA appId) {
	String s = {"app.", appId};
	return (*dcache)[s];
}

json::Value RpcInterface::findApp(json::StrViewA appId) {
	Result res = db->createQuery(appIndexView).includeDocs().key(appId).exec();
	return Row(res[0]).doc;
}

RpcInterface::AppInfo RpcInterface::getAppInfo(json::StrViewA appId, json::Value userdoc, bool force) {
	Value app = getApp(appId);
	if (!app.hasValue() && !force) return {};
	return getAppInfoFromDoc(appId, app, userdoc);
}

void RpcInterface::rpcSetUserEndpoints(json::RpcRequest req) {
	if (!req.checkArgs({{"string","number"},"string","string"})) return req.setArgError();
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.admin) {
			Value userdoc = searchUser(req.getArgs()[0]);
			if (userdoc.hasValue()) {
				String appid  = req.getArgs()[1].toString();
				String endpoint  = req.getArgs()[2].toString();
				Value app = findApp(appid);
				if (app.hasValue()) {
					Value e = app["endpoints"][endpoint];
					if (e.hasValue()) {
						userdoc = userdoc.replace(json::Path::root/"endpoint"/appid, endpoint);
						db->put(userdoc);
						req.setResult(true);
					} else {
						req.setError(451,"Unknown enpoint");
					}
				} else {
					req.setError(452,"Unknown app");
				}
			} else {
				req.setError(453,"Unknown user");
			}
		} else {
			req.setError(403,"Need admin");
		}
	}

}

void RpcInterface::rpcGetUserEndpoints(json::RpcRequest req) {
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.admin) {
			Value userdoc = searchUser(req.getArgs()[0]);
			if (userdoc.hasValue()) {
				String appid  = req.getArgs()[1].toString();
				Value app = findApp(appid);
				if (app.hasValue()) {
					auto appinfo = getAppInfoFromDoc(appid, app, userdoc);
					req.setResult(Object
							("name",userdoc["endpoint"][appid])
							("def",appinfo.endpoints)
							("app",appinfo.appId));
				} else {
					req.setError(452,"Unknown app");
				}
			} else {
				req.setError(453,"Unknown user");
			}

		} else {
			req.setError(403,"Need admin");
		}
	}

}

void RpcInterface::rpcAdminList(json::RpcRequest req) {
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.admin) {
			Value default_app = (*dcache)["default_app"];
			if (!default_app.hasValue()) default_app = Object("_rev","0");
			Result res = db->createQuery(0).prefixString("app.").exec();
			Value r (json::object,res.begin(), res.end(),[](Row x){return Value(x.id.getString(),x.value["rev"]);});
			r = r.replace("default_app",default_app["_rev"]);
			req.setResult(r);
		} else {
			req.setError(403,"Need admin");
		}
	}
}

void RpcInterface::rpcAdminAppList(json::RpcRequest req) {
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.admin) {
			Result res = db->createQuery(0).prefixString("app.").exec();
			Value r (json::array,res.begin(), res.end(),[](Row x){return x.id.getString().substr(4);});
			req.setResult(r);
		} else {
			req.setError(403,"Need admin");
		}
	}
}

void RpcInterface::rpcGetLastLogin(json::RpcRequest req) {
	if (!req.checkArgs({{"string","null","undefined"},{"number","undefined"},{"number","undefined"}})) return req.setArgError();
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.admin) {
			Value args = req.getArgs();
			Value app = args[0];
			Value offset = args[1];
			Value limit = args[2];
			if (!limit.hasValue()) std::swap(offset,limit);
			auto noffset = offset.getUInt();
			auto nlimit = limit.getUInt();
			if (nlimit == 0) nlimit = 100;
			auto q = db->createQuery(lastLoginView);
			q.includeDocs().reversedOrder().offset(noffset).limit(nlimit);
			if (app.hasValue()) q.prefixKey(app);
			else q.range(0,"");
			Result rs = q.exec();
			if (app.hasValue()) {
				req.setResult(rs.map([](Row rw)->Value{
					return {rw.key[1],rw.key[0], rw.id, Value(json::object,{rw.doc["email"], rw.doc["num_id"], rw.doc["cppd"]})};
				}));
			} else {
				req.setResult(rs.map([](Row rw)->Value{
					return {rw.key,rw.value, rw.id, Value(json::object,{rw.doc["email"], rw.doc["num_id"], rw.doc["cppd"]})};
				}));
			}
		} else {
			req.setError(403,"Need admin");
		}
	}
}

RpcInterface::AppInfo RpcInterface::getAppInfoFromDoc(json::StrViewA appId, json::Value app, json::Value userdoc) {
	Value defapp = (*dcache)["default_app"];
	if (defapp.type() == json::object) {
		app = defapp.merge(app);
	}

	bool cppd = userdoc["cppd"].getBool();
	Value id = app["id"];
	Value no_cppd_id = app["no_cppd_id"];
	Value res_appId = cppd?id:no_cppd_id;
	if (!res_appId.hasValue()) res_appId = id;
	if (!res_appId.hasValue()) res_appId = appId;

	Value endpoints = app["endpoints"];
	Value selendpoint = userdoc["endpoint"][appId];
	Value e = endpoints[selendpoint.getString()];
	if (!e.hasValue()) e = endpoints["_default"];

	return AppInfo{true,res_appId,e};
}

void RpcInterface::rpcAdminGenTokens(json::RpcRequest req) {
	if (!req.checkArgs({"number",Object
		("exp","number")
		("app","string")
		("roles",{{json::array,"string"},"undefined"})
	})) return req.setArgError();

	auto count = req.getArgs()[0].getUInt();
	Value cntr  = req.getArgs()[1];
	auto exp = cntr["exp"].getUInt();
	auto app = cntr["app"].getString();
	auto roles = cntr["roles"];
	auto ses = getSession(req);
	if (ses.valid) {
		if (ses.admin) {
			Array resp;
			for (decltype(count) i = 0; i < count; i++) {
				Value uid = db->genUID("r");
				auto s = createSession(uid, exp, app,false,roles);
				resp.push_back(s.first);
			}
			req.setResult(resp);
		}
	}
}

void RpcInterface::rpcUserId2Index(json::RpcRequest req) {
	Result res (db->createQuery(0).keys(req.getArgs()).includeDocs().exec());
	Value output = res.map([](Row rw)->Value{
		Value z =  rw.doc["num_id"];
		if (!z.hasValue()) return nullptr;
		return z;
	});
	req.setResult(output);
}

void RpcInterface::rpcUserIndex2Id(json::RpcRequest req) {
	Result res (db->createQuery(userIndexView).keys(req.getArgs()).exec());
	auto p = res.begin();
	Array output;
	for (Value z: req.getArgs()) {
		if (p == res.end()) {
			output.push_back(nullptr);
		} else {
			Row rw(*p);
			if (rw.key != z) {
				output.push_back(nullptr);
			} else {
				++p;
				output.push_back(rw.id.getString().startsWith("u")?rw.id:Value(nullptr));
			}
		}
	}

	req.setResult(output);
}
