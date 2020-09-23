cmake_minimum_required(VERSION 2.8) 

add_executable (loginserver main.cpp 
	sendmail.cpp 
	rpcinterface.cpp 
	loginApple.cpp 
	loginFacebook.cpp 
	loginGoogle.cpp
	loginTrezor.cpp 
	emailcodes.cpp
	rpcInterfaceOld.cpp
	invationsvc.cpp
	)
target_link_libraries (loginserver LINK_PUBLIC  simpleRpcServer simpleServer couchit imtjson ssl crypto stdc++fs pthread)
