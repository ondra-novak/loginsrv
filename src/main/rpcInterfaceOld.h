/*
 * rpcInterfaceOld.h
 *
 *  Created on: 13. 4. 2020
 *      Author: ondra
 */

#ifndef SRC_MAIN_RPCINTERFACEOLD_H_
#define SRC_MAIN_RPCINTERFACEOLD_H_

#include <main/rpcinterface.h>

class RpcInterfaceOld: public RpcInterface {
public:
	RpcInterfaceOld(const Config &cfg);

	virtual void initRPC(json::RpcServer &srv) override;

	virtual ~RpcInterfaceOld();

	void rpcUser2login(json::RpcRequest req);
	void rpcUser2create(json::RpcRequest req);
	void rpcUser2getEndPoints(json::RpcRequest req);
	void rpcUser2createRefreshToken(json::RpcRequest req);
	void rpcUser2whoami(json::RpcRequest req);

};

#endif /* SRC_MAIN_RPCINTERFACEOLD_H_ */
