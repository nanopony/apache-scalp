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
import os
import re
from datetime import datetime, time


class PermaJail:
    def __init__(self):
        try:
            with open('./jail.json') as rf:
                self.jail = set(json.load(rf))
        except:
            self.jail = set()

    def save(self):
        with open('./jail.json', 'w') as rf:
            json.dump(list(self.jail), rf)


class AbstractSignatureBase:
    SAFE = -1
    DONT_KNOW = 0

    def add_signature(self, signature, sev):
        pass;

    def save(self):
        pass;

    def analyse(self, ip, method, url, agent):
        """
        Gets request, returns heuristic level 0 - code blue, 10 - code red
        :param url:
        :param agent:
        :return:
        """
        return self.DONT_KNOW


class JsonSignatureBase(AbstractSignatureBase):
    def __init__(self):
        with open('./signature.json') as rf:
            raw = rf.read()
        self._json = json.loads(raw)
        self._compile_signatures()

    def _compile_signatures(self):
        self._signatures = []
        self._false_positives = []

        for s in self._json['signatures']:
            try:
                self._signatures.append((
                    re.compile(s['q'], re.I),
                    int(s['s']),
                ))
            except:
                print('%s rule is broken :c, skipping' % s['q'])
        for s in self._json['false_positives']:
            self._false_positives.append((
                re.compile(s, re.I),
            ))

    def add_signature(self, signature, sev=10):
        self._json['signatures'].append({'q': signature, 's': sev, 'tags': ['scan']})

    def save(self):
        with open('./signature_2.json', 'w') as rf:
            json.dump(self._json, rf)

    def analyse(self, ip, method, url, agent):
        """
        Gets request, returns heuristic level 0 - code blue, 10 - code red
        :param url:
        :param agent:
        :return:
        """
        for s in self._false_positives:
            if s[0].search(url):
                return self.SAFE

        for s in self._signatures:
            if s[0].search(url):
                return s[1]

        return self.DONT_KNOW


class Violator:
    def __init__(self, ip):
        self.ip = ip
        self.violations = []
        self.should_be_banned = False

    def pretty_print(self):
        print('Violator: %s %s' % (self.ip, '[BUSTED]' if self.should_be_banned else ''))
        print('Crimes:')

        for v in self.violations:
            print('  %s %s %s : %s' % v)
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
        print('# %s %s %s' % (method, url, agent))
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
        print('. %s %s %s' % (method, url, agent))
        self.violations.append((method, url, agent, 10))


class Anathema:
    def __init__(self, filename):
        self.filename = filename
        self.log_line_regex = re.compile(
            r'^([0-9\.]+)\s(.*)\[(.*)\]\s"([A-Z]+)\s*(.+)\sHTTP/\d.\d"\s(\d+)\s([\d]+)(\s"(.+)" )?(.*)$')
        self.malicious_malformed_line_regex = re.compile(
            r'^([0-9\.]+)\s(.*)\[(.*)\]\s"(.*)(\\x\d+)+(.*)"\s(\d+)\s([\d]+)(\s"(.+)" )?(.*)$')
        self.malformed_line_regex = re.compile(
            r'^([0-9\.]+)\s(.*)\[(.*)\]\s"(.+)"\s(\d+)\s([\d]+)(\s"(.+)" )?(.*)$')
        self.heuristic = JsonSignatureBase()

        self.purgitory = dict()
        self.jail = PermaJail()

    def parse_log(self):
        with open(self.filename) as log_file:
            for line_id, line in enumerate(log_file):
                m = self.log_line_regex.match(line)
                if m is not None:
                    ip, name, date, method, url, response, byte, _, referrer, agent = m.groups()

                    if ip in self.jail.jail:
                        if (ip not in self.purgitory):
                            self.purgitory[ip] = Violator(ip)
                        self.purgitory[ip].push_evidence(date, method, url, agent)
                        continue

                    if len(url) > 1 and method in ('GET', 'POST', 'HEAD', 'PUT', 'PUSH', 'OPTIONS'):
                        date = datetime.strptime(date, '%d/%b/%Y:%H:%M:%S %z')
                        sev = self.heuristic.analyse(ip, method, url, agent)
                        if (sev != self.heuristic.DONT_KNOW and sev != self.heuristic.SAFE):
                            if (ip not in self.purgitory):
                                self.purgitory[ip] = Violator(ip)
                            if self.purgitory[ip].push_violation(date, method, url, agent, sev):
                                self.jail.jail.add(ip)
                else:
                    m2 = self.malformed_line_regex.match(line)

                    if (m2 and self.malicious_malformed_line_regex.match(line)):
                        ip, name, date, url, response, byte, _, referrer, agent = m2.groups()
                        date = datetime.strptime(date, '%d/%b/%Y:%H:%M:%S %z')
                        if (ip not in self.purgitory):
                            self.purgitory[ip] = Violator(ip)
                        if self.purgitory[ip].push_violation(date, method, url, agent, 10):
                            self.jail.jail.add(ip)
                    else:
                        print('Bad line: %s' % line)
        for key, violator in self.purgitory.items():
            violator.pretty_print()

        self.jail.save()


    def learn(self, yes_to_all=False, dump_only=True):
        """
        Function to update signature base
        :return:
        """
        if len(self.jail.jail) == 0:
            return;
        print('Search for all violator activities which was not detected \n\n')
        new_signatures = set()

        with open(self.filename) as log_file:
            for line_id, line in enumerate(log_file):
                m = self.log_line_regex.match(line)
                if m is not None:
                    ip, name, date, method, url, response, byte, _, referrer, agent = m.groups()
                    if ip in self.jail.jail:
                        sev = self.heuristic.analyse(ip, method, url, agent)
                        if (sev == self.heuristic.DONT_KNOW and url not in new_signatures):
                            new_signatures.add(url)

                            if yes_to_all:
                                self.heuristic.add_signature(url, 10)
                            elif not dump_only:
                                q = input('New signature: %s; Add? [y]/n/q: ' % url)
                                if q in ['y', '', 'Y']:
                                    print('Ok')
                                    self.heuristic.add_signature(url, 10)
                                if q in ['q', 'Q']:
                                    self.heuristic.save()
                                    return
        if dump_only:
            PATH = './new_vectors'
            os.makedirs(PATH, exist_ok=True)
            curtime = datetime.now().strftime("%a-%d-%b-%Y")
            with open(os.path.join(PATH, 'new_vectors_%s_%s.txt'%(os.path.splitext(os.path.basename(self.filename))[0], curtime)),'w') as rp:
                rp.writelines([ l+'\n' for l in new_signatures])
        else:
            self.heuristic.save()


if __name__ == '__main__':
    a = Anathema('../../test/a_6.log')
    a.parse_log()
    a.learn()