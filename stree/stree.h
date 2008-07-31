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



// to use later the template stree<char>
typedef stree stree_c;

#endif

