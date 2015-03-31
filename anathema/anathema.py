#!/usr/bin/env python
"""
    Anathema heuristic module
    by Nanopony

    Copyright (c) 2015 Nanopony

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
"""
import json
import re
from datetime import datetime


class AbstractSignatureBase:
    def analyse(self, ip, method, url, agent):
        """
        Gets request, returns heuristic level 0 - code blue, 10 - code red
        :param url:
        :param agent:
        :return:
        """
        return 0


class JsonSignatureBase:
    def __init__(self):
        with open('./signature.json') as rf:
            raw = rf.read()
        self._json = json.loads(raw)
        self._compile_signatures()

    def _compile_signatures(self):
        self._signatures = []
        for s in self._json['signatures']:
            self._signatures.append((
                re.compile(s['q'],re.I),
                int(s['s']),
            ))
    def analyse(self, ip, method, url, agent):
        """
        Gets request, returns heuristic level 0 - code blue, 10 - code red
        :param url:
        :param agent:
        :return:
        """
        for s in self._signatures:
            if s[0].search(url):
                return s[1]
        return 0

class Violator:
    def __init__(self, ip):
        self.ip = ip
        self.violations = []
        self.should_be_banned = False
    def pretty_print(self):
        print('Violator: %s %s' % (self.ip, '[BUSTED]' if self.should_be_banned else ''))
        print('Crimes:')

        for v in self.violations:
            print('  %s %s %s : %s'%v)
        print('')
    def push_violation(self, date, method, url, agent, severity):
        """
            Violator isn't in jail
        :param date:
        :param method:
        :param url:
        :param agent:
        :param severity:
        :return:
        """
        self.latest_violation = date
        self.violations.append((method, url, agent, severity))
        self.should_be_banned = True
        return self.should_be_banned

    def push_evidence(self, date, method, url, agent):
        """
            Violator is in jail, we won't analyse his action to save time
        :param date:
        :param method:
        :param url:
        :param agent:
        :param severity:
        :return:
        """
        self.violations.append((method, url, agent, 10))


class Anathema:
    def __init__(self, filename):
        self.filename = filename
        self.log_line_regex = re.compile(
            r'^([0-9\.]+)\s(.*)\[(.*)\]\s"([A-Z]+)\s*(.+)\sHTTP/\d.\d"\s(\d+)\s([\d]+)(\s"(.+)" )?(.*)$')
        self.heuristic = JsonSignatureBase()

        self.purgitory = dict()
        self.jail = set()

    def parse_log(self):
        with open(self.filename) as log_file:
            for line_id, line in enumerate(log_file):
                m = self.log_line_regex.match(line)
                if m is not None:
                    ip, name, date, method, url, response, byte, _, referrer, agent = m.groups()
                    if ip in self.jail:
                        self.purgitory[ip].push_evidence(date, method, url, agent)
                        continue

                    if len(url) > 1 and method in ('GET', 'POST', 'HEAD', 'PUT', 'PUSH', 'OPTIONS'):
                        date = datetime.strptime(date, '%d/%b/%Y:%H:%M:%S %z')
                        sev = self.heuristic.analyse(ip, method, url, agent)
                        if (sev>0):
                            if (ip not in self.purgitory):
                                self.purgitory[ip] = Violator(ip)
                            if self.purgitory[ip].push_violation(date, method, url, agent, sev):
                                self.jail.add(ip)
        for key, violator in self.purgitory.items():
            violator.pretty_print()
if __name__ == '__main__':
    a = Anathema('../../test/satellite-access.log')
    a.parse_log()