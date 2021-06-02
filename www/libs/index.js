"use strict";



async function main() {

	var cur_session;

		
	var rpc = new RpcClient("/RPC");

	
	if (location.hash != "") {		
		var req = location.hash.substr(1).split('&').reduce((a,b)=>{var v = b.split('=');a[v[0]]=v[1];return a;},{})
		if (req.logged) {
			cur_session = req.ses;
			localStorage["refresh"] = req.rfr;
		}	
		location.hash = "";
	} else {
		var rfr = localStorage["refresh"];
		if (!rfr) {
			location.href="login.html";
		} else {	
			try {
				var lg = await rpc.call("Login.login",{
					provider:"token",
					token:rfr,
				});
				cur_session = lg.session;
			} catch (e) {
				location.href="login.html";	
			}
		}
	}

	rpc.context = {"session":cur_session};
	var me = await rpc.call("User.whoami");
	document.getElementById("uid").innerText = me.id;	

	document.getElementById("logout").addEventListener("click",()=>{
		delete localStorage["refresh"];
		location.href="login.html";	
	});
}