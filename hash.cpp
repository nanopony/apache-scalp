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
#include "hash.h"
using namespace std;

unsigned int hash(const string& str)
{
	unsigned int hash = 0;
	unsigned int x    = 0;
	for(std::size_t i = 0; i < str.length(); i++) {
		hash = (hash << 4) + str[i];
		if((x = hash & 0xF0000000L) != 0) {
			hash ^= (x >> 24);
		}
		hash &= ~x;
	}
   return hash;
}


unsigned int hash(const vector<string>& vect)
{
	unsigned int h=0;
	for (vector<string>::const_iterator iter=vect.begin();iter!=vect.end();++iter)
		h += hash(*iter);
	return h;
}


