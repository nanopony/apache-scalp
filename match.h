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
#ifndef __MATCH_H
#define __MATCH_H

#include <string>
#include <vector>


class Rule;

struct Match {
	Rule * rule;
	std::vector<std::string> tokens;

	Match() {}
	Match(Rule * const _rule, const std::vector<std::string>& _tokens)
	  : rule(_rule), tokens(_tokens)
	{}
	Match(const Match& m)
	  : rule(m.rule), tokens(m.tokens)
	{}
	
	~Match() {}
	
	inline Match& operator= (const Match& m) {
		rule = m.rule;
		tokens = m.tokens;
		return *this;	
	}
};



#endif

