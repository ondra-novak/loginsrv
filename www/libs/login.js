"use strict";


var server;


var controls = Array.prototype.reduce.call(document.querySelectorAll("[id]"),function(a, b) {
	a[b.id] = b;return a;
}, {});

[
	["provider_email","click",login_email_start],
	["email_enter_back","click",start_window],
	["email_enter_next","click",login_email_request],
	["email_code_back","click",login_email_start],
	["email_code_next","click",login_email_finish],
	["email_address","input",function(){controls.email_enter_next.disabled = this.value.indexOf('@')==-1;clearErrors();}],
	["email_code","input",function(){controls.email_code_next.disabled = this.value == "";clearErrors();}],
	["new_account_back","click",start_window],
	["new_account_create","click",()=>fn_create_account()],
	["new_account_connect","click",()=>fn_connect_account()],
	["stop_connect","click",stop_connect],
	["provider_trezor","click",trezorLogin],
	["provider_facebook","click",loginFacebook]
	
	
].forEach(x=>{
	document.getElementById(x[0]).addEventListener(x[1],x[2]);
});


var shownErrors = [];

var cur_session;
var cur_refresh;
var cur_new_token;
var cur_window; 
var default_action;
var cancel_action;
var appId;
var allow_admin;
var target_url;
var endpoint_name;
var trezor_challenge;
var googleUser = {};


function loadLibrary(path) {
	return new Promise(function(ok, error){
			var script = document.createElement("script");
			script.src = path
			script.onload = ()=>{
				console.log("A library loaded: "+path);
				ok();
			},
			script.onerror = ()=>{
				console.error("Failed to load a library: "+path);
				error(arguments);
			}
			document.body.appendChild(script);		
	});
}


async function main() {
	try {
		var conf = await fetch("conf/login.conf").then(x=>x.json());
		await loadLibrary(conf.rpc_path+"/rpc.js");		
		var rpc_client = new RpcClient(conf.rpc_path);
		server = await rpc_client.createObject();
		document.addEventListener("keydown",function(ev) {
			if (!ev.shiftKey && !ev.ctrlKey && !ev.altKey) {
				if (ev.code=="Enter" && default_action) {
					ev.preventDefault();
					controls[default_action].click();
				} else if (ev.code=="Escape" && cancel_action) {
					ev.preventDefault();
					controls[cancel_action].click();
				}
			}
		});	
		appId = conf.app;
		allow_admin = conf.allow_admin;
		target_url = conf.target_url;
		endpoint_name = conf.endpoint_name;
		var lp = [];
		if (conf.trezor) {					
			trezor_challenge = conf.trezor.challenge;
			lp.push(
				loadLibrary("libs/trezor-connect.js").then(()=>{
					return TrezorConnect.manifest(conf.trezor.manifest);	
				}).then(()=>{
					controls.provider_trezor.hidden = false;
				})
			)
		}
		if (conf.google) {
			lp.push(
				loadLibrary("https://apis.google.com/js/api:client.js").then(()=>{
					gapi.load('auth2', function(){      		
				      	var auth2 = gapi.auth2.init({
				        	client_id: conf.google.client_id,
				        	cookiepolicy: 'single_host_origin',
					   		  });
			      		googleLogin(auth2);
			      		controls.provider_google.hidden = false;
			    	});						
				})
			)
		}
		if (conf.facebook) {
			window.fbAsyncInit = function() {
			   FB.init({
			      appId            : conf.facebook.appId,
			      status 		   : false,
			      xfbml            : false,
			      version          : 'v10.0'
    		   });
    		   controls.provider_facebook.hidden = false;
			};
			lp.push(
				loadLibrary("https://connect.facebook.net/en_US/sdk.js").then(()=>{
						
				})
			)
		}
			
		await Promise.all(lp);
		start_window();
	} catch (e) {
		document.write(e.toString());
	}
}


function show(id) {
	if (cur_window) {
		controls[cur_window].classList.add("closed");
		return new Promise(function(ok) {
			setTimeout(function() {
					controls[cur_window].hidden = true;
					controls[id].hidden = false;
					controls[id].classList.remove("closed");
					cur_window = id;
				ok()
			},500);
		});
	} else {
		cur_window = id;
		controls[id].hidden = false;
		controls[id].classList.remove("closed");
		return Promise.resolve(0);
	}
}

function hideCurWindow() {
	if (cur_window) {
		controls[cur_window].classList.add("closed");
		return new Promise(function(ok) {
			setTimeout(function() {
					controls[cur_window].hidden = true;
					cur_window = null;
				ok()
			},500);
		});
	} else {
		return Promise.resolve(0);
	}
}

function showError(err) {
	clearErrors();
	Array.prototype.forEach.call(document.getElementsByClassName(err),function(x) {
		x.classList.add("shown");
		shownErrors.push(x);
	});
}

function clearErrors() {
	shownErrors.forEach(x=>x.classList.remove("shown"));
	shownErrors=[];
}

async function start_window() {
	show("choose_provider");
	clearErrors();
	default_action = null;
	cancel_action = null;
}

async function login_email_start() {
	clearErrors();
	controls.email_address.value="";
	controls.email_enter_next.disabled=true;
	await show("email_enter");
	controls.email_address.focus();
	cancel_action = "email_enter_back";
	default_action = "email_enter_next";
		
}

function login_email_request() {
	controls.email_enter_next.disabled=true;
	server.Login.requestCode(controls.email_address.value,appId)
		.then(()=>{
			clearErrors();		
			controls.email_code.value="";
			controls.email_code_next.disabled=true;
			show("email_code_enter").then(()=>{controls.email_code.focus();});
			cancel_action="email_code_back";
			default_action="email_code_next";
		})
		.catch(()=>{
			showError("err_empty");
		})
}

function login_email_finish() {
	controls.email_code_next.disabled=true;
	server.Login.login({
		provider:"email",
		email:email_address.value,
		token:email_code.value,
		app:appId,
		admin:allow_admin}).then(r=>{
			login_continue(r);
		})
		.catch (()=>{
			showError("err_invcode");
		})		
}


var fn_create_account;
var fn_connect_account;


function start_connect(token) {
	cur_new_token = token;
	controls.top_toast.hidden = false;
}

function stop_connect() {
	cur_new_token = null;
	controls.top_toast.hidden = true;
}


function new_account(token) {
	stop_connect();
	cancel_action = "new_account_back";
	default_action = "new_account_create";
	controls.new_account_create.disabled=false;

	fn_create_account = async function() {
		try {
			controls.new_account_create.disabled=true;
			var res = await server.Login.signup(token,true);
			login_continue(await server.Login.login({
				provider:"token",
				token:res.token,
				app:appId}));
		} catch (e) {
			start_window();
		}
	}
	
	fn_connect_account = function() {
		start_connect(token);
		start_window();
	}

	show("new_account_option");
	
}

async function trezorLogin() {
			
		var time = (new Date()).toJSON().replace('T',' ').substr(0,16);
		var challenge = trezor_challenge + " ("+time+")";
		var resp = await Promise.all([TrezorConnect.requestLogin({
			  "challengeHidden":"00000000","challengeVisual":challenge}), hideCurWindow()]);
		var resp = resp[0];
		if (resp.success && resp.payload && resp.payload.publicKey && resp.payload.signature) {
			var token = resp.payload.publicKey+"|"+resp.payload.signature+"|"+challenge;
			login_continue(await server.Login.login({
				provider:"trezor",
				token:token,
				app:appId,
				admin:allow_admin}));
		} else {
			start_window();		
		}
	}


function googleLogin(auth2) {
    auth2.attachClickHandler(controls.provider_google, {},
        function(googleUser) {
        	var token = googleUser.qc.id_token;
        	server.Login.login({
        		provider:"google",
        		token:token,
				app:appId,
				admin:allow_admin}).then(login_continue);        		        	
        }, function(error) {
          showError("google_err");
        });
 }


function loginFacebook() {
	FB.login(function(response) {
	    if (response.authResponse) {
        	var token = response.authResponse.accessToken;
        	server.Login.login({
        		provider:"facebook",
        		token:token,
				app:appId,
				admin:allow_admin}).then((r)=>{
					FB.logout(function(){
						login_continue(r);
					});
				});        		        		             
        } else {
    	     showError("facebook_err");
	    }
	});

}

async function login_continue(r) {
	if (r.new_user) {
		new_account(r.signup_token);	
	} else {
		if (endpoint_name) {
			var e = r.endpoints[endpoint_name];
			if (e) target_url = e;
		}
		if (target_url.indexOf('#') == -1) target_url = target_url + '#';
		var args = {"ses":r.session,
		 "rfr":r.refresh,
		 "exp":r.expiration};
		var hash_args = Object.keys(args).map(x=>(x+"="+encodeURIComponent(args[x]))).join("&");
		target_url = target_url + hash_args;
		
		if (cur_new_token) {
			await server.Login.addProvider(cur_new_token);
		}
		
		await hideCurWindow();
		location.href = target_url;				
	}
}

