#include <memory>
#include <thread>
#include <couchit/config.h>
#include <couchit/couchDB.h>
#include <couchit/exception.h>
#include <couchit/memview.h>
#include <imtjson/jwtcrypto.h>
#include <imtjson/rpc.h>
#include <main/rpcinterface.h>
#include <main/sendmail.h>
#include <openssl/sha.h>
#include <shared/default_app.h>
#include <shared/linux_crash_handler.h>
#include <shared/logOutput.h>
#include <shared/stringview.h>
#include <userver/async_provider.h>
#include <userver/netaddr.h>
#include <userver/static_webserver.h>
#include "server.h"

using couchit::CouchDB;
using json::RpcRequest;
using ondra_shared::DefaultApp;
using ondra_shared::logDebug;
using ondra_shared::logError;
using ondra_shared::logFatal;
using ondra_shared::logProgress;
using ondra_shared::StrViewA;
using json::BinaryView;
using userver::NetAddr;
using userver::NetAddrList;


class App: public DefaultApp {
public:
	App():DefaultApp({},std::cerr) {}
	virtual void showHelp(const std::initializer_list<Switch> &defsw) override;
	int run();

};

std::shared_ptr<CouchDB> initDB(const ondra_shared::IniConfig::Section &s) {
	couchit::Config cfg;
	cfg.baseUrl = s.mandatory["url"].getString();
	cfg.databaseName = s.mandatory["name"].getString();
	cfg.authInfo.username = s.mandatory["login"].getString();
	cfg.authInfo.password = s.mandatory["password"].getString();
	return std::make_shared<CouchDB>(cfg);
}

using PECKey = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
PECKey initKey(const ondra_shared::IniConfig::Section &s) {
	auto secret = s.mandatory["secret"].getString();
	unsigned char key[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char *>(secret.data), secret.length,key);
	return PECKey(json::JWTCrypto_ES::importPrivateKey(256,BinaryView(key, sizeof(key))), &EC_KEY_free);
}

static void specAccountsView(const json::Value &doc, const couchit::EmitFn &emit) {
	if (doc["force_code"].defined()) {
		emit(doc["email"],doc["force_code"]);
	}
}

int App::run() {
	auto section_server = config["server"];

	auto db = initDB(config["database"]);
	auto chdist = std::make_shared<couchit::ChangesDistributor>(*db);
	PECKey pkey = initKey(config["private_key"]);
	std::string pubkey = json::JWTCrypto_ES::exportPublicKeyPEM(pkey.get());
    json::PJWTCrypto jwt = new json::JWTCrypto_ES(pkey.release(), 256);

	SendMail sendmail(config["sendmail"].mandatory["path"].getPath());

	auto bind_addr = NetAddr::fromStringMulti(section_server.mandatory["bind"].getString(),"36989");
	for (const NetAddr &b: bind_addr) {
		logProgress("Bind to address: $1", b.toString(false));
	}

	auto asyncProvider = userver::createAsyncProvider(std::max<unsigned int>(1,section_server["dispatchers"].getUInt(1)));
	auto asyncThreads = std::max<unsigned int>(1,section_server.mandatory["threads"].getUInt());


/*    AsyncProvider asyncProvider = ThreadPoolAsync::create(

                    ));
*/

    couchit::MemView specAccounts((couchit::MemViewDef(specAccountsView)));
    chdist->add(specAccounts);

    unsigned int cacheSize = std::max<unsigned int>(config["user_cache"].mandatory["size"].getUInt(),100);

    std::shared_ptr<RpcInterface> rpcifc;
    {
    	RpcInterface::Config rpccfg{sendmail,jwt,db,*chdist,specAccounts, cacheSize};
    	rpcifc = std::make_shared<RpcInterface>(std::move(rpccfg));
    }

    logProgress("Initializing server");
    MyHttpServer server;

    server.addRPCPath("/RPC", {true,true,true,65536});
    server.add_ping();
    server.add_listMethods();
    server.addPath("/public_key",[&](userver::PHttpServerRequest &req, std::string_view ) {
    	if (req->allowMethods({"GET"})) {
    		req->setContentType("text/plain");
    		req->send(pubkey);
    	}
    	return true;
    });
    rpcifc->initRPC(server);

    if (config["num_ids"].mandatory["enable"].getBool()) {
    	rpcifc->initNumIDSvc(*chdist);
    }

    server.addPath("/_up",[&](userver::PHttpServerRequest &req, std::string_view ) {
    	db->createQuery(0).limit(0).exec();
    	req->setContentType("text/plain");
    	req->send("OK");
    	return true;
    });
    auto webPath = config["web"]["path"].getPath(std::string());
    if (!webPath.empty()) {
    	server.addPath("", userver::StaticWebserver({webPath,"login.html"}));
    }

//TODO    server.addStats("/stats");


    chdist->runService([asyncProvider]{
    		userver::setCurrentAsyncProvider(asyncProvider);
    });
    server.start(bind_addr, asyncThreads, asyncProvider);

    specAccounts.update(*db);

    server.stopOnSignal();
    server.addThread();
	chdist->stopService();
	return 0;

}


void App::showHelp(const std::initializer_list<Switch> &defsw) {
	const char *commands[] = {
			"",
			"Commands",
			"",
			"start        - start service on background",
		    "stop         - stop service ",
			"restart      - restart service ",
		    "run          - start service at foreground",
			"status       - print status",
			"pidof        - print pid",
			"wait         - wait until service exits",
	};

	const char *intro[] = {
			"Usage: loginserver [...switches...] <command> [<args...>]",
			""
	};

	for (const char *c : intro) wordwrap(c);
	ondra_shared::DefaultApp::showHelp(defsw);
	for (const char *c : commands) wordwrap(c);
}

static ondra_shared::CrashHandler report_crash([](const char *line) {
	ondra_shared::logFatal("CrashReport: $1", line);
});

int main(int argc, char **argv) {

	App app;


	if (!app.init(argc, argv)) {
		std::cerr << "Invalid arguments. Use -h for help" << std::endl;
		return 1;
	}

	report_crash.install();

	try {

		app.run();

	} catch (std::exception &e) {
		logFatal("Top level exception: $1", e.what());
		std::cerr << "Service failed to initialize" << std::endl;

	}

	return 0;
}

