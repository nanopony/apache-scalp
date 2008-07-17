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
#include <list>
#include <fstream>
#include <ctime>
#include <boost/xpressive/xpressive.hpp>
#include <memory>

#include "config.h"

#ifdef MULTI_THREAD
  #include <boost/smart_ptr.hpp>
  #include <boost/thread/mutex.hpp>
  #include "threadpool.hpp"
  
  using namespace boost::threadpool; 
#endif

#include <boost/program_options.hpp> 
#include "loken.h"
#include "rule.h"
#include "match.h"

using namespace std;
using namespace boost::xpressive;


//const char *apache_re = "(\\d+\\.\\d+\\.\\d+\\.\\d+) - (.*)\\[(.+)-(\\d+)\\] \"([A-Z]+)?(.*) HTTP/\\d.\\d\" (\\d{3}) (\\d+)(\\s\".+\"\\s)?(\".+\")?";
const char *apache_re = "(\\d+\\.\\d+\\.\\d+\\.\\d+) - ([\\w\\-\\s]*)\\[([^\\s]+) -(\\d+)\\] \"(GET|POST|HEAD|TRACE)?(.+) HTTP/\\d.\\d\" (\\d{3}) (\\d+)(\\s\".+\"\\s)?(\".+\")?";
int const subs[] = {3, 5, 6};


#ifdef MULTI_THREAD
boost::mutex result_lock;

class LineProcess {
	boost::mutex mutex;
	
	std::vector<std::string> toks;
	const RuleFactory& factory;
	const sregex& apache_log;
	list<Match *>& results;
  public:

	LineProcess(const std::vector<std::string>& t, const RuleFactory& f, const sregex& a, list<Match *>& r)
	  : toks(t), factory(f), apache_log(a), results(r)
	{ }

	void run() {
		boost::mutex::scoped_lock lk(mutex);
		Rule *res;
		if (factory.pre_selected(toks[2]) && (res=factory.check_one(toks[2]))) {
			boost::mutex::scoped_lock lres(result_lock);
			results.push_back(new Match(res,toks));
		}
	}
	~LineProcess() {}
};
#endif


int main(int argc, char *argv[])
{
	RuleFactory factory;

	// the regexp to extract the content of the apache log
	// using Boost.Xpressive for speed here!
	static sregex apache_log = sregex::compile(apache_re, regex_constants::optimize);
	string filter_xml  = "default_filter.xml";
	string access_file = "access_log";
	
	// only interested in date, method and URL
	if (argc > 1) {
		filter_xml = argv[1];
		if (argc > 2) {
			access_file = argv[2];
		}
	}
	
	factory.load(filter_xml);
	if (factory.fails()) {
		cout << "Error" << endl;
		return 0;	
	}	

	size_t loc=0, nb_lines=50000;
	clock_t start=0, end=0;
	string line;
	vector<Match *> results;
	vector<string>  toks;

	ifstream inf(access_file.c_str());
	if (inf.is_open()) {
#ifdef MULTI_THREAD
		pool threadpool(NB_THREAD);
#endif
		start = clock();
		while(true) 
		{
			if (getline(inf, line).eof())
				break;
			sregex_token_iterator cur(line.begin(), line.end(), apache_log, subs);
			sregex_token_iterator end;
			for( ; cur != end; ++cur )
				toks.push_back(*cur);
			if (toks.size() == 3) {
#ifdef MULTI_THREAD		
				boost::smart_ptr<LineProcess> job(new LineProcess(toks,factory,apache_log,results));
				schedule(threadpool,boost::bind(&LineProcess::run, job));
#else
				Rule *res;
				if (factory.pre_selected(toks[2]) && (res=factory.check_one(toks[2]))) {
					results.push_back(new Match(res,toks));
				}
#endif
			}
			toks.clear();
			if (nb_lines > 0 && loc > nb_lines)
				break;
			++loc;
		}
#ifdef MULTI_THREAD
		threadpool.wait();
#endif
		end = clock();
	}
	end = (1000 * (end - start)) / CLOCKS_PER_SEC;
	float n = float(end) / 1000.00;
	cout << loc << " lines analyzed in " << n << " seconds" << endl;
	cout << results.size() << " possible warnings found" << endl;

	for(vector<Match *>::iterator iter=results.begin(); iter!=results.end();++iter)
		delete *iter;

	return 0;
}

