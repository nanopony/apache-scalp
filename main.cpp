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

#include "loken.h"
#include "converter.h"
#include "rule.h"
#include "match.h"
#include "output.h"

using namespace std;
using namespace boost::xpressive;


//const char *apache_re = "(\\d+\\.\\d+\\.\\d+\\.\\d+) - (.*)\\[(.+)-(\\d+)\\] \"([A-Z]+)?(.*) HTTP/\\d.\\d\" (\\d{3}) (\\d+)(\\s\".+\"\\s)?(\".+\")?";
const char *apache_re = "(\\d+\\.\\d+\\.\\d+\\.\\d+) - ([\\w\\-\\s]*)\\[([^\\s]+) [-|+](\\d+)\\] \"(GET|POST|HEAD|TRACE)?(.+) HTTP/\\d.\\d\" (\\d+) (\\d+)(\\s\".+\"\\s)?(\".+\")?";
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

static bool contains(const std::string& str, const std::string& in) {
	return str.find(in) != std::string::npos;
}


void help() {
	cout << "Scalp the apache log! - http://rgaucher.info" << endl;
	cout << "usage:  ./scalp.py [--log|-l log_file] [--filters|-f filter_file] [--period time-frame] [OPTIONS] [--attack a1,a2,..,an]" << endl;
	cout << "   --log       |-l:  the apache log file './access_log' by default" << endl;
	cout << "   --filters   |-f:  the filter file     './default_filter.xml' by default" << endl;
	//cout << "   --exhaustive|-e:  will report all type of attacks detected and not stop" << endl;
	//cout << "                     at the first found" << endl;
	cout << "   --period    |-p:  the period must be specified in the same format as in" << endl;
	cout << "                     the Apache logs using * as wild-card"  << endl;
	cout << "                     ex: 04/Apr/2008:15:45;*/Mai/2008" << endl;
	cout << "                     if not specified at the end, the max or min are taken" << endl;
	cout << "   --html      |-h:  generate an HTML output" << endl;
	cout << "   --xml       |-x:  generate an XML output" << endl;
	cout << "   --text      |-t:  generate a simple text output (default)" << endl;
	//cout << "   --except    |-c:  generate a file that contains the non examined logs due to the" << endl;
	//cout << "                     main regular expression; ill-formed Apache log etc." << endl;
	//cout << "   --attack    |-a:  specify the list of attacks to look for" << endl;
	//cout << "                     list: xss, sqli, csrf, dos, dt, spam, id, ref, lfi" << endl;
	//cout << "                     the list of attacks should not contains spaces and comma separated" << endl;
	//cout << "                     ex: xss,sqli,lfi,ref" << endl;
	cout << "   --order     |-o:  sort the output by: impact,regexp or attack" << endl;
	cout << "                       ex: --order impact" << endl;
	cout << "                       to sort by impact (higher first)" << endl;
	cout << "   --reverse   |-r:  reverse the order for the output (needs --order set)" << endl;
}


int main(int argc, char *argv[])
{
	RuleFactory factory;
	// the regexp to extract the content of the apache log
	// using Boost.Xpressive for speed here!
	static sregex apache_log = sregex::compile(apache_re, regex_constants::optimize);
	//
	string filter_xml  = "default_filter.xml";
	string access_file = "access_log";
	string output      = "";
	string period      = "";
	string order       = "";
	bool   reverse     = false;

	for(int i=1; i<argc; i++) {
		string s = argv[i];
		if ((s == "--log" || s == "-l") && i < argc-1)
			access_file = argv[i+1];
		else if ((s == "--filters" || s == "-f") && i < argc-1)
			filter_xml = argv[i+1];
		else if ((s == "--period" || s == "-p") && i < argc-1)
			period = argv[i+1];
		else if (s == "--html") output += "html,";
		else if (s == "--text") output += "text,";
		else if (s == "--xml")  output += "xml,";
	}
	if (output.empty())
		output = "text"; // default text output
	
	factory.load(filter_xml);
	if (factory.fails()) {
		cout << "Error" << endl;
		return 0;	
	}	

	size_t loc=0, nb_lines;
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

	if (!order.empty()) {
		// sort the results table...
		
	}

	if (output == "xml") {
		XMLOutput xmlOutput(access_file + "-out.xml", access_file);
		for(vector<Match *>::iterator iter=results.begin(); iter!=results.end();++iter)
			xmlOutput << **iter;
	}
	else if (output == "html") {
		HTMLOutput htmlOutput(access_file + "-out.html", access_file);
		for(vector<Match *>::iterator iter=results.begin(); iter!=results.end();++iter)
			htmlOutput << **iter;
	}
	else if (output == "text") {
		Output textOutput(access_file + "-out.txt", access_file);
		for(vector<Match *>::iterator iter=results.begin(); iter!=results.end();++iter)
			textOutput << **iter;
	}
	
	
	// clear the structure..
	for(vector<Match *>::iterator iter=results.begin(); iter!=results.end();++iter)
		delete *iter;

	return 0;
}

