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
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <ctime>
#include <cstdlib>
using namespace std;

#ifndef srand48
  #define srand48 srand
  #define lrand48 rand
#endif


string genRWord(const unsigned short length = 16) {
	static const string ref = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static const short  refL = ref.length();
	string ret;

	srand48(time(NULL) + lrand48() % 65527);
	ret += ref[((lrand48() % (refL-36))) + 36]; // start with a caps
	for (unsigned short i=1; i < length; i++)
		ret += ref[((lrand48() % refL))];
	return ret;
}

string genRText(const unsigned int t_length, float density, map<string, string>& m) {
	string out;
	const unsigned int num  = (unsigned int )((float)t_length * density);
	const unsigned int step = (unsigned int)(t_length / num);
	
	vector<string> words;
	for(map<string,string>::const_iterator iter=m.begin(); iter!=m.end(); ++iter)
		words.push_back(iter->first);
	const unsigned int size = words.size();
	unsigned int index;
	
	for(unsigned int i = 0; i < t_length; i++) {
		if (!(num % step)) {
			// using a word from the list
			index = lrand48() % size;
			out += words[index];
		}
		else
			out += genRWord(2 + lrand48() % 32);
		out += " ";
	}
	return out;
}

