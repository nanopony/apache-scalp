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
#ifndef __CONVERTER_H
#define __CONVERTER_H

#include <map>
#include <string>
#include <vector>
#include "stree/stree.h"

class Converter {
	bool inited;
	stree_c *t;
	std::map<std::string, std::string> m;

  public:
	Converter() : inited(false), t(0) {}
	
	void add(const std::string& search, const std::string& replace, bool i = false);
	
	inline void init() {
		if (m.size() > 0) {
			t = new stree(m);		
			inited = true;
		}
	}

	inline std::string transform(const std::string& in) const {
		return inited ? t->replace(in) : in;
	}


	void print();

	~Converter() {
		if (t) delete t;
	}
	
  public:
	static std::string base64_detect(const std::string& input);
	static std::string base64_decode(const std::string& input);
	
};

#endif

