/*
  Copyright (c) 2008 Romain Gaucher <r@rgaucher.info>

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0
                
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
*/
#include <fstream>
#include <iostream>
#include <utility>
#include <vector>
#include <algorithm>
#include <map>
#include <cassert>
#include <pcrecpp.h>
#include "hash.h"
#include "rule.h"
using namespace std;
using namespace boost::xpressive;
using namespace pcrecpp;

namespace utils {
	void replace(string& where, const string& what, const string& by) {
		for (string::size_type 	i  = where.find(what);
		                        i != string::npos;
		                        i  = where.find(what, i + by.size()))
			where.replace(i, what.size(), by);
	}
}

unsigned int Rule::hash() const {
	return ::hash(regexp);
}

bool Rule::has_type(const std::string& type) const {
	for (vector<string>::const_iterator iter=tags.begin();iter!=tags.end();++iter)
		if (type == *iter)
			return true;
	return false;
}


ostream& operator<<(ostream& out, const Rule& rule) {
	out << rule.impact << ',' << rule.regexp << '|' << rule.description;
	return out;
}



bool RuleFactory::fails() const {
	return _fails;
}


string getContent(xmlNode *a_node) {
	xmlChar *c = xmlNodeGetContent(a_node);
	string ret((char *)c);
	utils::replace(ret, "\n", "");
	utils::replace(ret, "\r", "");
	utils::replace(ret, "\b", "");	
	xmlFree(c);
	return ret;
}

string getChildName(xmlNode *node) {
	string content;
	if (node->type == XML_ELEMENT_NODE)
		content = (char *)node->name;
	else if (node->type == XML_TEXT_NODE)
		content = getContent(node);
	return content;
}

void RuleFactory::walk(xmlNode *a_node, vector<Element>& buffer) {
	xmlNode *cur_node = 0;
	string name, value;
	for (cur_node = a_node; cur_node; cur_node = cur_node->next) 
	{
		if (cur_node->type == XML_ELEMENT_NODE) {
			name = (char *)cur_node->name;
			if (cur_node->children->type == XML_TEXT_NODE)
				value = getChildName(cur_node->children);
			if (!name.empty() && !value.empty()) {
				buffer.push_back(Element(name, value));
				name.clear(); 
				value.clear();
			}
		}
		walk(cur_node->children, buffer);
	}
}

int RuleFactory::getTagIndex(const vector<string>& locals) const {
	int min = 99;
	for (unsigned int i=0;i<tags.size();i++) {
		string t = tags[i];
		for (vector<string>::const_iterator jter=locals.begin(); jter!=locals.end(); ++jter) {
			if (t == *jter)
				if (i < static_cast<unsigned int>(min)) min = i;				
		}
	}
	return min == 99 ? -1 : min;
}

void RuleFactory::load(const string& filename) {	
	xmlDoc *doc = 0;
	xmlNode *root_element = 0;

	doc = xmlReadFile(filename.c_str(), 0, XML_PARSE_NOCDATA|XML_PARSE_NONET);
	if (doc == 0) {
		cout << "error: could not parse file :" << filename << endl;
		_fails = true;
		return;
	}

	vector<Element> buffer;
	root_element = xmlDocGetRootElement(doc);
	walk(root_element,buffer);
	xmlFreeDoc(doc);
	xmlCleanupParser();

	// then fill the structure based on the vector
	string rule, description;
	vector<string> tok_tags;
	unsigned int impact=0;
	size_t nb_tags = 0, max_impact=0, nb_rules = 0;
	
	for(vector<Element>::const_iterator iter  = buffer.begin();
	                                    iter != buffer.end()  ;
	                                  ++iter                  ) {
		// fill the tags
		if (iter->first == "tag" && find(tags.begin(), tags.end(), iter->second) == tags.end())
			tags.push_back(iter->second);
		else if (iter->first == "impact") {
			unsigned int loc_impact=0;
			from_string<unsigned int>(loc_impact, iter->second);
			if (loc_impact > max_impact)
				max_impact = loc_impact;
		}
	}
	nb_tags = tags.size();
	                           
	                                  
	for(vector<Element>::const_iterator iter  = buffer.begin();
	                                    iter != buffer.end()  ;
	                                  ++iter                  ) {

		if (iter->first == "filter") {
			if (!rule.empty() && !description.empty() && impact > 0 && tags.size() > 0) {
				Rule temp;
				temp.description = description;
				temp.regexp = rule;
				temp.impact = impact;
				temp.tags = tok_tags;

				temp.compiled = new RE(rule, RE_Options().set_utf8(false));			
//#define TAG_HASH
//#define IMPACT_HASH
//#define DUMB_HASH

#ifdef TAG_HASH
				unsigned long  k = (1 << (32 - nb_tags + getTagIndex(tok_tags))) 
				                 + (1 << (32 - nb_tags - max_impact + temp.impact)) 
				                 + nb_rules;
#elif defined(DUMB_HASH)
				unsigned long k = nb_rules;
#else
				unsigned long  k = (1 << (32 - max_impact + impact)) 
				                 + (1 << (32 - max_impact - nb_tags + getTagIndex(tok_tags))) 
				                 + nb_rules;
#endif
				factory[k] = new Rule(temp);				
				tok_tags.clear();				
			}
		}
		else if (iter->first == "description")
			description = iter->second;
		else if (iter->first == "rule")
			rule = iter->second, ++nb_rules;
		else if (iter->first == "tag")
			tok_tags.push_back(iter->second);		
		else if (iter->first == "impact")
			from_string<unsigned int>(impact, iter->second);
	}
		
#if 0
	for (map<unsigned long, Rule *>::const_iterator iter=factory.begin();iter!=factory.end();++iter) {
		cout << iter->first << " -> " << iter->second->impact << "  ";
		for(vector<string>::const_iterator jter=iter->second->tags.begin(); jter!= iter->second->tags.end(); ++jter)
			cout << *jter << ',';
		cout << endl;
	}
#endif

	// instanciante the pre_selection regular expression
	correct_url = sregex::compile("^(\\s*)/([\\w/\\.]*)([\\.\\w]*)$", regex_constants::optimize);
}


/**
	The pre-selection tries to look for common URL patterns in order to
	speed up the decision of rejecting a possible URL for containing 
	attacks
*/
bool RuleFactory::pre_selected(const string& url) const {
	smatch what;
	if (regex_match(url, what, correct_url))
		return false;	
	return true;
}


Rule * RuleFactory::check_one(const string& url) const {
	for (map<unsigned long, Rule *>::const_iterator iter=factory.begin();iter!=factory.end();++iter) {
		if (iter->second->compiled->PartialMatch(url.c_str())) {
			return iter->second;
		}		
	}
	return (Rule *)0;
}

vector<Rule *> RuleFactory::check_all(const string& url) const {
	vector<Rule *> rules;
	for (map<unsigned long, Rule *>::const_iterator iter=factory.begin();iter!=factory.end();++iter) {
		if (iter->second->compiled->PartialMatch(url.c_str())) {
			rules.push_back(iter->second);
		}		
	}
	return rules;
}

vector<Rule *> RuleFactory::check_type(const string& url, const string& type) const {
	vector<Rule *> rules;
	for (map<unsigned long, Rule *>::const_iterator iter=factory.begin();iter!=factory.end();++iter) {
		if (iter->second->has_type(type) && (iter->second->compiled->PartialMatch(url.c_str()))) {
			rules.push_back(iter->second);
		}	
	}
	return rules;
}


RuleFactory::~RuleFactory() {
	// be sure to destroy all the rules
	for (map<unsigned long, Rule *>::iterator iter=factory.begin();iter!=factory.end();++iter) {
		if (iter->second) {
			delete iter->second->compiled;
			delete iter->second;
		}	
	}
}

