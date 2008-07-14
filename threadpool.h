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
#ifndef __THREADPOOL_H
#define __THREADPOOL_H

#include <list>
#include <vector>
#include <queue>
#include <boost/any.hpp>
#include <pthread.h>

struct Result {
	std::vector<boost::any> results;
};

struct Params {
	std::vector<boost::any> params;
};


class ThreadJob {
	unsigned int id;
  public:
	ThreadJob(unsigned int n) : id(n) {}
	virtual void execute(const Params& , Result& ) {
		// do the processing here...
		return;
	}
	virtual ~ThreadJob() {} = 0;
};


class ThreadPool {
	unsigned short p;

	std::list          <ThreadJob *> current;
	std::priority_queue<ThreadJob *>    pool;

	unsigned int         maxThreads, 
	                  activeThreads;
	bool                     active;
	
  public:

	ThreadPool(unsigned short nb_proc = 2)
	  : p(nb_proc)
	{}
	
	ThreadPool& assign(ThreadJob* job);
	
	bool empty() const;
};



#endif

