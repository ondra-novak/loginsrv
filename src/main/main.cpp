#include <shared/default_app.h>
#include <shared/logOutput.h>
#include <shared/stringview.h>
#include <simpleServer/abstractService.h>

using ondra_shared::DefaultApp;
using ondra_shared::logDebug;
using ondra_shared::logFatal;
using ondra_shared::StrViewA;
using simpleServer::ArgList;
using simpleServer::ServiceControl;


int svcmain(ServiceControl &cntr, ArgList ) {

	cntr.dispatch();
	return 0;

}

class App: public DefaultApp {
public:
	App():DefaultApp({},std::cerr) {}

	virtual void showHelp(const std::initializer_list<Switch> &defsw) {
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
};

int main(int argc, char **argv) {

	App app;

	if (!app.init(argc, argv)) {
		std::cerr << "Invalid arguments. Use -h for help" << std::endl;
		return 1;
	}
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
			return svcmain(cntr, arglist);
		},args,false);

	} catch (std::exception &e) {
		logFatal("Top level exception: $1", e.what());
		std::cerr << "Service failed to initialize" << std::endl;

	}

	return 0;
}

