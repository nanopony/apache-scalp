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
#ifndef __LOKEN_H
#define __LOKEN_H

#include <string>
#include <sstream>

template <class T>
bool from_string(T& t, const std::string& s) {
	std::istringstream iss(s, std::istringstream::in);
	return !(iss >> t).fail();	
}

template <class T>
std::string to_string(const T& t) {
	std::ostringstream oss;
	oss << t;
	return oss.str();
}


struct Date {
	unsigned short day;
	unsigned short month;
	unsigned short year;
	unsigned short hour;
	unsigned short minute;
	unsigned short second;	
	
	Date() {}
	
	Date(const Date& d)
	  : day(d.day), month(d.month),year(d.year),
	    hour(d.hour),minute(d.minute),second(d.second)
	{}
	
	Date(const std::string&, const std::string& conf = "dMYhms");
	
	Date& operator=(const Date& d) {
		day = d.day; month = d.month; year = d.year;
		hour = d.hour; minute = d.minute; second = d.second;
		return *this;
	}	
};

// implements operators for the dates
/*
bool operator<  (const Date&, const Date&);
bool operator<= (const Date&, const Date&);

bool operator>  (const Date&, const Date&);
bool operator>= (const Date&, const Date&);

bool operator== (const Date&, const Date&);
bool operator!= (const Date&, const Date&);
*/



/**
	Simple struct to contain the elements in the 
	log
*/
class Loken {
	std::string  method;
	std::string     url;
	Date           date;

  public:
	Loken() {}
	Loken(const std::string& d, const std::string& m, const std::string& u);
	
	Loken(const Loken& l)
	  : method(l.method), url(l.url), date(l.date)
	{}
	
	~Loken() {}
	
	inline Loken& operator=(const Loken& l) {
		method = l.method;
		url = l.url;
		date = l.date;
		return *this;	
	}
	
	inline void setMethod(const std::string& m ) { method = m; }
	inline std::string getMethod() const         { return method; }
	
	void setUrl(const std::string& u)            { url = u; }
	std::string getUrl() const                   { return url; }
	
	void setDate(const Date& d)                  { date = d; }     
	Date getDate() const                         { return date; }

};



#endif
