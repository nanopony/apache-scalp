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
#include "loken.h"
using namespace std;



static const string Months[] = {"Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"};

unsigned int monthIndex(const string& _m) {
	unsigned int i=0;
	for (;i<12;i++)
		if (Months[i] == _m)
			return i;
	// error
	return i;
}

bool is_alpha(const string& s) {
	for (string::const_iterator iter=s.begin();iter!=s.end();++iter)
		if (isalpha(*iter))
			return true;
	return false;
}

Date::Date(const string& s, const string& conf) {
	if (s[0] == '/' || s[0] == ':')
		return;
	vector<unsigned int> tokens;
	unsigned int i, item=0;
	bool error = false;	
	string::const_iterator iter=s.begin(), start=s.begin();	
	for(;iter!=s.end();++iter) {
		if (*iter == '/' || *iter == ':') {
			string::const_iterator end=iter;
			string temp(start,end);
			
			if (!is_alpha(temp))
				error = from_string<unsigned int>(i,temp);
			else if (conf[item] == 'M')
				error = (((i = monthIndex(temp)) >= 12) ? true : false);
			else {
				// bad configuration...
				return;			
			}
			if (error) return;						
			tokens.push_back(i);
			++item;
			start = iter; ++start;
		}
	}

	string temp(start,s.end());
	if (!is_alpha(temp))
		error = from_string<unsigned int>(i,temp);
	else if (conf[item] == 'M')
		error = (((i = monthIndex(temp)) >= 12) ? true : false);
	else {
		// bad configuration...
		return;			
	}
	
	if (error)
		return;						
	tokens.push_back(i);
	
	// set the date
	unsigned int l = conf.length();
	for (i=0;i<l;i++) {
		switch(conf[i])
		{
			case 'd': day    = tokens[i]; break;
			case 'M': month  = tokens[i]; break;			
			case 'y': year   = tokens[i]; break;		
			case 'h': hour   = tokens[i]; break;					
			case 'm': minute = tokens[i]; break;		
			case 's': second = tokens[i]; break;		
			default:
				break;
		}
	}
}


Loken::Loken(const string& d, const string& m, const string& u) {
	date = Date(d);
	method = m;
	url = u;
}




