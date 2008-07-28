/*
  Copyright (c) 2008 Romain Gaucher <r@rgaucher.info>
                             -- http://rgaucher.info

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0
                
  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
  
    -- 
  
  The STree's are an implementation of a fast replacements algorithm
  based on a dictionnary.
  
  Using the stree is simple:
  
	  map<string, string> replacements;
	  // fill the map with the pair (to_find, to_replace_with)
	  // and of course, the key is unique (ie. no multi-replacements)
	  
	  string my_text;
	  stree_c my_tree(replacements);
	  string replaced_text = my_tree.replace(my_text);

*/
#ifndef __STREE_H
#define __STREE_H

#include <map>
#include <string>
#include <iostream>
#include "tree.hh"

class stree {
  public:
	typedef tree<char> c_tree;

  protected:
	c_tree t;
	c_tree::iterator root;
	std::map<std::string, std::string> m;
	
  protected:
  	stree() {}
	stree(const stree&) {}
	stree& operator=(const stree&) {return *this;}	
	
	void init();
	void insert(const std::string&);
	c_tree::sibling_iterator child_exists(const c_tree::iterator& root, const char c);
	
  public:
	stree(const std::map<std::string, std::string>& _m)
	  : m(_m)
	{
		init();
	}
	
	std::string replace(const std::string& in);
	void print(const c_tree::iterator& root, std::string padding = "");
	
	~stree() {}
};


inline void stree::print(const stree::c_tree::iterator& r, std::string padding) {
	for(c_tree::sibling_iterator iter=t.begin(r); iter!=t.end(r); ++iter) {
		std::cout << padding << *iter << std::endl;
		print(iter, padding + " ");
	}
}

inline stree::c_tree::sibling_iterator stree::child_exists(const stree::c_tree::iterator& root, const char c) {
	for(c_tree::sibling_iterator iter=t.begin(root); iter!=t.end(root); ++iter) {
		if (c == *iter)
			return iter;
	}
	return t.end(root);
}


void stree::init() {
	root = t.begin();
	t = t.insert(root, '#');
	for (std::map<std::string,std::string>::const_iterator iter=m.begin(); iter!=m.end(); ++iter) {
		insert(iter->first);
	}
}


void stree::insert(const std::string& input) {
	c_tree::iterator iter = root;
	c_tree::sibling_iterator kter;
	bool insert_rest = false;
	for(std::string::const_iterator jter=input.begin(); jter!=input.end(); ++jter) {
		if (!insert_rest) {
			if ((kter=child_exists(iter, *jter)) != t.end(root))
				iter = kter;
			else 
				insert_rest = true;
		}
		if (insert_rest)
			iter = t.append_child(iter, *jter);
	}
}

std::string stree::replace(const std::string& str) {
	std::string out,s;
	c_tree::sibling_iterator kter, lter;
	std::map<std::string,std::string>::iterator mter;

	const size_t length = str.length();
	size_t i,j;
	char c;	

	for (i=0;i<length;i++) {
		// catch to see if the current character is a possible beginning 
		// of a pattern to match
		c = str[i];
		if ((kter=child_exists(root, c)) != t.end(root)) {
			lter=kter; j=i;
			do {
				if (str[j] != 0)
					s += str[j];
				++j; // next character
				kter = lter;
			}
			while ((lter=child_exists(lter, str[j])) != t.end(lter) && j < length);
			// is lter a terminal node?
			if(t.number_of_children(kter) == 0 && !s.empty()) {
				if ((mter = m.find(s)) != m.end())
					out += mter->second;
				i = j;
			}
			s.clear();
		}
		if (str[i] != 0)
			out += str[i];
	}
	return out;
}

// to use later the template stree<char>
typedef stree stree_c;

#endif

