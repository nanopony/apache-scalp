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
#include <fstream>
#include <ctime>
#include "rule.h"
#include "match.h"
#include "output.h"
using namespace std;





static const string xml_header = "<!-- \n\
  File created by Scalp! by Romain Gaucher - http://code.google.com/p/apache-scalp\n\
  Apache log attack analysis tool based on PHP-IDS filters\n\
-->\n\
<?xml version=\"1.0\" encoding=\"utf-8\"?>";


static const string txt_header = "#\n\
# File created by Scalp! by Romain Gaucher - http://code.google.com/p/apache-scalp\n\
# Apache log attack analysis tool based on PHP-IDS filters";



string xml_entities(const string& name) {
	string out = "";
	for (string::const_iterator iter=name.begin(); iter!=name.end(); ++iter) {
		switch (*iter) {
			case '\"': out += "&quot;"; break;
			default:
				out += *iter;
				break;
		}		
	}
	return out;
}

string enumerate_types(const vector<string>& v) {
	string out;
	if (v.size() < 1)
		return "";
	out = v[0];	
	for (unsigned int i=1;i<v.size();i++) {
		out += "," + v[i];
	}
	return out;
}

string clean_str(const string& in) {
	string out = ""; 
	for (string::const_iterator iter=in.begin(); iter!=in.end(); ++iter) {
		switch (*iter) {
			case '\n': continue; break;
			default:
				out += *iter;
				break;
		}		
	}
	return out;
}

void Output::header() {
	stream << txt_header << endl;
	time_t t;
	struct tm * timeinfo;
	time ( &t );
	timeinfo = localtime ( &t );
	stream << "# Log File: " << log << endl;
	stream << "# Generated: " << asctime(timeinfo) << endl;
}

void Output::footer() {
	return;
}

Output& operator<<(Output& out, const Match& match) {
	if (!out.fails) {
		out.stream << match.rule->description << endl;
		out.stream << match.rule->impact << endl;
		out.stream << match.rule->regexp << endl;
		out.stream << match.tokens[1] << " - " << match.tokens[2] << endl; 
		out.stream << endl;
	}
	return out;
}


void XMLOutput::header() {
	stream << xml_header << endl;
	time_t t;
	struct tm * timeinfo;
	time (&t);
	timeinfo = localtime ( &t );
	stream << "<scalp time=\"" << clean_str(asctime(timeinfo)) << "\" file=\"" << log <<"\">" << endl;	
}


void XMLOutput::footer() {
	stream << "</scalp>";
}

XMLOutput& operator<< (XMLOutput& out, const Match& match) {
	if (!out.fails) {
		out.stream << " <attack type=\""  << enumerate_types(match.rule->tags) << "\">" << endl;
		out.stream << "  <impact>" << match.rule->impact << "</impact>" << endl;
		out.stream << "  <item>" << endl;
		out.stream << "    <line><![CDATA[" << match.tokens[2] << "]]></line>" << endl;
		out.stream << "    <reason><![CDATA[" << match.rule->description << "]]></reason>" << endl;
		out.stream << "    <regexp><![CDATA[" << match.rule->regexp << "]]></regexp>" << endl;
		out.stream << "  </item>" << endl;
		out.stream << " </attack>" << endl;
	}
	return out;
}




