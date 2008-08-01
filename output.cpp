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


static const string html_header = "<html><head><style>\
html, body {background-color:#ccc;color:#222;font-family:'Lucida Grande',Verdana,Arial,Sans-Serif;font-size:0.8em;line-height:1.6em;margin:0;padding:0;}\n\
body {background-color:#fff;padding:0; margin: 15px; border: 1px solid #444;}\n\
h1 {	display: block;	border-bottom: 2px solid #333;	padding: 5px;}\n\
h2 { display: block; font-size: 1.1em; font-weight: normal;}\n\
.match { display: block; margin: 10px; border: 1px solid; padding: 5px;}\n\
.impact { float: right; background-color: #fff; border: 1px solid #ccc; padding: 5px; font-size: 1.8em;}\n\
.impact-1,.impact-2,          { background-color: #f2ffe0; border-color: #DEF0C3;}\n\
.impact-3,.impact-4,.impact-5 { background-color: #ffe6bf; border-color: #ffd38f;}\n\
.impact-6,.impact-7,.impact-8 { background-color: #FFEDEF; border-color: #FFC2CA;}\n\
.highlight {margin: 5px;}\n\
.reason {font-weight: 700; color: #444;}\n\
.line, .regexp {border-bottom: 1px solid #ccc; border-right: 1px solid #ccc; background-color: #fff; padding: 2px; margin: 10px;}\n\
#footer {text-align: center;}\n\
</style></head><body>";


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

string html_entities(const string& name) {
	string out = "";
	for (string::const_iterator iter=name.begin(); iter!=name.end(); ++iter) {
		switch (*iter) {
			case '\"': out += "&quot;"; break;
			case '>' : out += "&gt;";   break;
			case '<' : out += "&lt;";   break;
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

void HTMLOutput::header() {
	stream << html_header << endl;
	time_t t;
	struct tm * timeinfo;
	time (&t);
	timeinfo = localtime ( &t );
	stream << "<h1>Scalp of " << log << " on " << clean_str(asctime(timeinfo)) << "</h1>" << endl;	
}


void HTMLOutput::footer() {
	stream << "<div id='footer'>Scalp by Romain Gaucher &lt;r@rgaucher.info&gt; - <a href='http://rgaucher.info'>http://rgaucher.info</a></footer></body></html>";
}

HTMLOutput& operator<< (HTMLOutput& out, const Match& match) {
	if (!out.fails) {
		out.stream << "<div class='match impact-" << match.rule->impact << "'>" << endl;
		out.stream << "<div class='impact'>Impact " << match.rule->impact << "</div>" << endl;
		out.stream << "<h2>Attack detected: "  << html_entities(enumerate_types(match.rule->tags)) << "</h2>" << endl;
		out.stream << "  Reason: <span class='reason'>" << html_entities(match.rule->description) << "</span><br />" << endl;
		out.stream << "<div class='highlight'>" << endl;
		out.stream << "  <span class='line'><b>Log line:</b>&nbsp;" << html_entities(match.tokens[2]) << "</span><br />" << endl;
		out.stream << "  <span class='regexp'><b>Matching Regexp:</b>&nbsp;" << html_entities(match.rule->regexp) << "</span>" << endl;
		out.stream << "</div>" << endl;
		out.stream << "</div>" << endl;
	}
	return out;
}




