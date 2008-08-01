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
#ifndef __OUTPUT_H
#define __OUTPUT_H

#include <iostream>
#include <fstream>
#include <string>

class Match;

class Output {
  protected:
	bool           fails;
	std::ofstream stream;
	std::string      log;
		
  protected:
	Output() {}
	Output(const Output&) {}
	Output& operator=(const Output&) {return *this;}	
	
	void header();
	void footer();
	
  public:
	Output(const std::string& fname, const std::string& logfile) : fails(true), stream(fname.c_str()), log(logfile) {
		if (stream.is_open()) {
			fails = false;
			header();
		}
	}
	
	virtual ~Output() {
		footer();
		stream.close();
	}
	
	friend Output& operator<<(Output& , const Match& );
};

Output& operator<<(Output& , const Match& );



class XMLOutput {
  protected:
	bool           fails;
	std::ofstream stream;
	std::string      log;
	
  protected:
	XMLOutput() {}
	XMLOutput(const XMLOutput&) {}
	XMLOutput& operator=(const XMLOutput&) {return *this;}	
	
	void header();
	void footer();
	
  public:
	XMLOutput(const std::string& fname, const std::string& logfile) : fails(true), stream(fname.c_str()), log(logfile) {
		if (stream.is_open()) {
			fails = false;
			header();
		}
	}
	
	virtual ~XMLOutput() {
		footer();
		stream.close();
	}
	
	friend XMLOutput& operator<<(XMLOutput& , const Match& );
};

XMLOutput& operator<< (XMLOutput&, const Match&);


class HTMLOutput {
  protected:
	bool           fails;
	std::ofstream stream;
	std::string      log;
	
  protected:
	HTMLOutput() {}
	HTMLOutput(const HTMLOutput&) {}
	HTMLOutput& operator=(const HTMLOutput&) {return *this;}	
	
	void header();
	void footer();
	
  public:
	HTMLOutput(const std::string& fname, const std::string& logfile) : fails(true), stream(fname.c_str()), log(logfile) {
		if (stream.is_open()) {
			fails = false;
			header();
		}
	}
	
	virtual ~HTMLOutput() {
		footer();
		stream.close();
	}
	
	friend HTMLOutput& operator<<(HTMLOutput& , const Match& );
};

HTMLOutput& operator<< (HTMLOutput&, const Match&);


#endif
