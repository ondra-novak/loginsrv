#include <thread>
#include <couchit/config.h>
#include <couchit/couchDB.h>
#include <couchit/exception.h>
#include <couchit/memview.h>
#include <imtjson/jwtcrypto.h>
#include <rpc/rpcServer.h>
#include <imtjson/rpc.h>
#include <main/invationsvc.h>
#include <main/rpcinterface.h>
#include <main/rpcInterfaceOld.h>
#include <main/sendmail.h>
#include <openssl/sha.h>
#include <shared/default_app.h>
#include <shared/linux_crash_handler.h>
#include <shared/logOutput.h>
#include <shared/stringview.h>
#include <simpleServer/abstractService.h>
#include <simpleServer/address.h>
#include <simpleServer/asyncProvider.h>
#include <simpleServer/http_filemapper.h>
#include <simpleServer/threadPoolAsync.h>
#include <memory>

using couchit::CouchDB;
using json::RpcRequest;
using ondra_shared::DefaultApp;
using ondra_shared::logDebug;
using ondra_shared::logError;
using ondra_shared::logFatal;
using ondra_shared::logProgress;
using ondra_shared::StrViewA;
using simpleServer::ArgList;
using simpleServer::AsyncProvider;
using simpleServer::NetAddr;
using simpleServer::RpcHttpServer;
using simpleServer::ServiceControl;
using simpleServer::ThreadPoolAsync;


class App: public DefaultApp {
public:
	App():DefaultApp({},std::cerr) {}
	virtual void showHelp(const std::initializer_list<Switch> &defsw) override;
	int run(ServiceControl &cntr, ArgList);

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

int App::run(ServiceControl &cntr, ArgList) {
	auto section_server = config["server"];
	cntr.changeUser(section_server["user"].getString());

	auto db = initDB(config["database"]);
	auto chdist = std::make_shared<couchit::ChangesDistributor>(*db);
	PECKey pkey = initKey(config["private_key"]);
	std::string pubkey = json::JWTCrypto_ES::exportPublicKeyPEM(pkey.get());
    json::PJWTCrypto jwt = new json::JWTCrypto_ES(pkey.release(), 256);

	SendMail sendmail(config["sendmail"].mandatory["path"].getPath());

    NetAddr bind_addr = NetAddr::create(section_server.mandatory["bind"].getString(),36989);
    logProgress("Bind to address: $1", bind_addr.toString());

    AsyncProvider asyncProvider = ThreadPoolAsync::create(
                    std::max<unsigned int>(1,section_server.mandatory["threads"].getUInt()),
                    std::max<unsigned int>(1,section_server["dispatchers"].getUInt(1)));


    std::shared_ptr<InvationSvc> invsvc;
    if (config["invationAPI"]["enable"].getBool(false)) {
    	auto key = config["invationAPI"].mandatory["key"].getString();
    	invsvc = std::make_shared<InvationSvc>(std::string(key));
    }

    couchit::MemView specAccounts((couchit::MemViewDef(specAccountsView)));
    chdist->add(specAccounts);

    unsigned int cacheSize = std::max<unsigned int>(config["user_cache"].mandatory["size"].getUInt(),100);

    std::shared_ptr<RpcInterface> rpcifc;
    {
    	RpcInterface::Config rpccfg{sendmail,jwt,db,*chdist,specAccounts,invsvc.get(), cacheSize};
    	rpcifc = config["oldAPI"]["enable"].getBool(false)?
						std::make_shared<RpcInterfaceOld>(std::move(rpccfg)):
						std::make_shared<RpcInterface>(std::move(rpccfg));
    }

    logProgress("Initializing server");
    RpcHttpServer server(bind_addr, asyncProvider);
	server.setHostMapping(section_server["mapHosts"].getString(""));

    server.addRPCPath("/RPC");
    server.add_ping();
    server.add_listMethods();
    server.addPath("/public_key",[&](simpleServer::HTTPRequest req, StrViewA ) {
    	if (req.allowMethods({"GET"})) {
    		req.sendResponse("text/plain",pubkey);
    	}
    	return true;
    });
    rpcifc->initRPC(server);

    if (config["num_ids"].mandatory["enable"].getBool()) {
    	rpcifc->initNumIDSvc(*chdist);
    }

    server.addPath("/_up",[&](simpleServer::HTTPRequest req, StrViewA) {
    	db->createQuery(0).limit(0).exec();
    	req.sendResponse("text/plain","OK");
    	return true;
    });
    auto webPath = config["web"]["path"].getPath(std::string());
    if (!webPath.empty()) {
    	server.addPath("", simpleServer::HttpFileMapper(std::move(webPath),"login.html"));
    }

    server.addStats("/stats");
	cntr.enableRestart();


    chdist->runService();
    server.start();

    specAccounts.update(*db);

	cntr.dispatch();
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

		StrViewA cmd = app.args->getNext();
		if (cmd.empty()) {
			std::cerr << "Command required. Use -h for help" << std::endl;
			return 1;
		}
		std::string control_file = app.config["service"].mandatory["control_file"].getPath();
		auto args = app.getArgs();
		ServiceControl::create("loginserver", control_file, cmd,
				[&](ServiceControl cntr, StrViewA , ArgList arglist) {
			return app.run(cntr, arglist);
		},args,false);

	} catch (std::exception &e) {
		logFatal("Top level exception: $1", e.what());
		std::cerr << "Service failed to initialize" << std::endl;

	}

	return 0;
}

