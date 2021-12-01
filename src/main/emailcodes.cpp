/*
 * emailcodes.cpp
 *
 *  Created on: 13. 4. 2020
 *      Author: ondra
 */

#include <couchit/document.h>
#include <couchit/result.h>
#include <couchit/view.h>
#include <couchit/query.h>
#include <imtjson/object.h>
#include <imtjson/value.h>
#include <main/emailcodes.h>
#include <shared/stringview.h>
#include <map>

using couchit::Document;
using couchit::Result;
using couchit::Row;
using couchit::View;
using json::Object;
using json::Value;
using ondra_shared::StrViewA;

EmailCodes::EmailCodes(const std::shared_ptr<couchit::CouchDB> &db):db(db),rnd(std::random_device()()) {
}

unsigned int EmailCodes::generateCode(json::String email) {

	std::unique_lock _(lock);
	auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
	Value doc = db->get("email_codes",db->flgCreateNew|db->flgNodeLocal);
	Value codes = doc["codes"];
	unsigned int dupreq = 0;
	if (codes.hasValue()) {
		codes = codes.filter([&](Value z){
			if (z.getKey() == email && z["exp"].getIntLong() > now+870)
				dupreq = z["code"].getUInt();
			return z["exp"].getIntLong() > now && z["tries"].getUInt() < 10;
		});
	} else {
		codes = json::object;
	}
	if (dupreq)
		return dupreq;
	std::uniform_int_distribution<unsigned int> rndst(10000,99999);
	int randomCode = rndst(rnd);
	codes = codes.replace(email, Object{
		{"exp",now+900},
		{"tries",0},
		{"code", randomCode}});
	db->put(doc.replace("codes",codes));
	return randomCode;
}

bool EmailCodes::checkCode(json::String email, unsigned int code) {
	std::unique_lock _(lock);
	auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
	Result items = db->createQuery(View::includeDocs).prefixString("email_codes").exec();
	std::map<std::string_view, Value> mergmap;
	for (Row rw: items) {
		Value codes = rw.doc["codes"];
		for (Value x: codes) {
			if (x["exp"].getIntLong() >= now) {
				auto iter = mergmap.find(x.getKey());
				if (iter == mergmap.end()) {
					mergmap.emplace(x.getKey(), x);
				} else {
					auto exp1 = iter->second["exp"].getUIntLong();
					auto exp2 = x["exp"].getUIntLong();
					auto try1 = iter->second["tries"].getUInt();
					auto try2 = x["tries"].getUInt();
					if (exp1 < exp2 || (exp1 == exp2 && try1 < try2)) {
						iter->second = x;
					}
				}
			}
		}
	}

	auto iter = mergmap.find(email);
	if (iter == mergmap.end()) return false;

	bool suc = false;

	Value found = iter->second;
	auto tries = found["tries"].getUInt();
	if (found["code"].getUInt() == code && tries < 10) {
		suc = true;
		found = found.replace("tries",999999);
	} else {
		found = found.replace("tries", tries+1);
	}
	Document doc = db->get("email_codes",db->flgCreateNew|db->flgNodeLocal);
	{
		auto codes = doc.object("codes");
		codes.set(email, found);
	}
	db->put(doc);
	return suc;


}
