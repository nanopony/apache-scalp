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
#include <fstream>
#include <ctime>
#include <boost/xpressive/xpressive.hpp>
#include <memory>


#include "threadpool.h"

#include "loken.h"
#include "rule.h"
#include "match.h"

using namespace std;
using namespace boost::xpressive;

static const char *apache_re = "^(\\d+\\.\\d+\\.\\d+\\.\\d+) - (.*)\\[(.+)-(\\d+)\\] \"([A-Z]+)?(.*) HTTP/\\d.\\d\" (\\d{3}) (\\d+)(\\s\".+\"\\s)?(\".+\")?$";
int const subs[] = {3, 5, 6};

struct Params {
	const string& line;
	const RuleFactory& factory;
	const sregex& apache_log;
	vector<Match *>& results;

	Params(const string& l, const RuleFactory& f, const sregex& a, vector<Match *>& r)
	  : line(l), factory(f), apache_log(a), results(r)
	{}

  private:
	Params& operator=(const Params&) {return *this;}
};

/*
class LineProcess : public TThreadPool::TJob
{
	const Params& p;
  public:
	LineProcess(int np, const Params& params) : TThreadPool::TJob(np), p(params) {}
	void run(void *arg) {
		Rule *res = 0;
		vector<string> toks;
		sregex_token_iterator cur(p.line.begin(), p.line.end(), p.apache_log, subs);
		sregex_token_iterator end;
		for( ; cur != end; ++cur ) {
			toks.push_back(*cur);
		}
		if (toks.size() == 3 && p.factory.pre_selected(toks[2]) && (res=p.factory.check_one(toks[2]))) {
			p.results.push_back(new Match(res,toks));			
			res=0;
		}
	}
};

*/
class LineProcess : public Thread
{
  public:
	void execute(const Params& params) {
		Rule *res = 0;
		vector<string> toks;
		sregex_token_iterator cur(p.line.begin(), p.line.end(), p.apache_log, subs);
		sregex_token_iterator end;
		for( ; cur != end; ++cur ) {
			toks.push_back(*cur);
		}
		if (toks.size() == 3 && p.factory.pre_selected(toks[2]) && (res=p.factory.check_one(toks[2]))) {
			p.results.push_back(new Match(res,toks));			
			res=0;
		}
		return 0;
	}
	~LineProcess() {}
};



int main(int argc, char *argv[])
{
	unsigned short NB_THREAD = 5;
	RuleFactory factory;
	// TThreadPool  * thread_pool;
	ThreadPool* thread_pool;


	// the regexp to extract the content of the apache log
	// using Boost.Xpressive for speed here!
	sregex apache_log = sregex::compile(apache_re, regex_constants::optimize);
	string access_file = "access_log";
	
	// only interested in date, method and URL
	if (argc > 1) {
		factory.load(argv[1]);
		if (factory.fails()) {
			cout << "Error" << endl;
			return 0;	
		}
		if (argc > 2) {
			access_file = argv[2];
		}
	}

	ifstream inf(access_file.c_str());
	if (!inf.is_open()) {
		cout << "cannot open the file" << endl;
		return 0;
	}

	size_t loc=0, nb_lines = 0;
	
	string temp;
	vector<Match *> results;
	
	
	clock_t start = clock();
	//--
	
	thread_pool = new ThreadPool(NB_THREAD);

	while(true) 
	{
		if (getline(inf, temp).eof())
			break;
		
		// ugly!!! need to change the design once TP is finished
		thread_pool->assign(new LineProcess(Params(temp,factory,apache_log,results)));
		
		if (nb_lines > 0 && loc > nb_lines)
			break;
		++loc;
	}
	while(!thread_pool->empty())
		;

	delete thread_pool;
	//--
		
	clock_t end = (1000 * (clock() - start)) / CLOCKS_PER_SEC;
	float n = float(end) / 1000.00;
	cout << loc << " lines analyzed in " << n << " seconds" << endl;
	cout << results.size() << " possible warnings found" << endl;		

	for(vector<Match *>::iterator iter=results.begin(); iter!=results.end();++iter)
		delete *iter;
	return 0;
}

