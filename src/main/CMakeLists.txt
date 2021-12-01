cmake_minimum_required(VERSION 2.8) 

add_executable (loginserver main.cpp 
	sendmail.cpp 
	rpcinterface.cpp 
	loginApple.cpp 
	loginFacebook.cpp 
	loginGoogle.cpp
	loginTrezor.cpp 
	emailcodes.cpp
	server.cpp
	)
target_link_libraries (loginserver LINK_PUBLIC  userver_jsonrpc userver couchit imtjson ssl crypto stdc++fs pthread)
