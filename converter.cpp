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
#include <string>
#include <vector>
#include <iostream>
#include <sstream>
#include "converter.h"
using namespace std;

void Converter::add(const std::string& _search, const std::string& replace, bool i) {
	string s = _search;
	if (m.find(s) == m.end()) {
		m[s] = replace;
		if (i) {
			std::transform(s.begin(), s.end(), s.begin(), (int(*)(int))toupper);
			m[s] = replace;
		}
	}
}

void Converter::print() {
	for (map<string,string>::const_iterator iter=m.begin(); iter!=m.end(); ++iter)
		cout << iter->first << " -> " << iter->second << endl;
}


