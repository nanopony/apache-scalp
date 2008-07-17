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
#ifndef __RULE_H
#define __RULE_H

#include <iostream>
#include <fstream>
#include <map>
#include <vector>
#include <list>
#include <boost/xpressive/xpressive.hpp>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <pcrecpp.h>
#include "loken.h"


/**
	Simple struct to contain a single rule
*/
struct Rule {
	unsigned int      impact;
	std::string  description;
	std::string       regexp;
	pcrecpp::RE *   compiled;
	
	std::vector<std::string> tags;

  public:
	inline Rule& operator=(const Rule& rule) {
		if (this != &rule) {
			impact = rule.impact;
			description = rule.description;
			regexp = rule.regexp;
			compiled = rule.compiled;
			tags = rule.tags;	
		}
		return *this;
	}
	
	Rule() {}
	
	Rule(const Rule& rule) {
		impact = rule.impact;
		description = rule.description;
		regexp = rule.regexp;
		compiled = rule.compiled;
		tags = rule.tags;	
	}	

	unsigned int hash() const;
	bool has_type(const std::string& ) const;
	friend std::ostream& operator<<(std::ostream&, const Rule& );
};

std::ostream& operator<<(std::ostream&, const Rule& );

/**
	Simple container with copelien form
*/
struct Element {
	std::string first;
	std::string second;

	Element() {}
	Element(const Element& e) : first(e.first), second(e.second) {}
	Element(const std::string& f, const std::string& s) : first(f), second(s) {}
	~Element(){};
	Element& operator=(const Element& e) {
		first = e.first;
		second = e.second;
		return *this;
	}
};

/**
	Contains all the rules and load/compile them from the 
	given filter XML files
*/
class RuleFactory {
	std::vector<std::string>            tags;
	std::map<unsigned long, Rule *> factory;
	std::list<Rule *>                lRules;
	bool                             _fails;
	boost::xpressive::sregex    correct_url;

  private:
	RuleFactory(const RuleFactory& ){}
	RuleFactory& operator=(const RuleFactory& ){return *this;}

	void walk(xmlNode *a_node, std::vector<Element>& buffer);
	int getTagIndex(const std::vector<std::string>&) const;


  public:
  	~RuleFactory();
  
	RuleFactory() : _fails(false) {}

	bool fails() const;
	void load(const std::string& filename);
	
	Rule *              check_one (const std::string& ) const;
	std::vector<Rule *> check_all (const std::string& ) const;
	std::vector<Rule *> check_type(const std::string& , const std::string& ) const;

	bool pre_selected(const std::string& ) const;
};





#endif

