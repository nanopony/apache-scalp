Scalp! is a log analyzer for the Apache web server that aims to look for security problems. The main idea is to look through huge log files and extract the possible attacks that have been sent through HTTP/GET (By default, Apache does not log the HTTP/POST variable).

It is a code migration from GoogleCode (one of thousand, I feel); I will definitely look forward to developing some additional heuristics 

## How it works
Scalp is basically using the regular expression from the PHP-IDS project and matches the lines from the Apache access log file. These regexp has been chosen because of their quality and the top activity of the team maintaining that project.

You will then need this file https://dev.itratos.de/projects/php-ids/repository/raw/trunk/lib/IDS/default_filter.xml in order to run Scalp.

Scalp started as a simple python script which is still maintained, but I plan to focus my effort on the binary version (written in C++) for efficiency when it comes to scalp huge log files.

### Usage
Scalp has a couple of options that may be useful in order to save time when scalping a huge log file or in order to perform a full examination; the default options are almost okay for log files of hundreds of MB.

Current options:

- exhaustive: Won't stop at the first pattern matched, but will test all the patterns
- tough: Will decode a part of potential attacks (this is done to use better the regexp from PHP-IDS in order to - decrease the false-negative rate)
- period: Specify a time-frame to look at, all the rest will be ignored
- sample: Does a random sampling of the log lines in order to look at a certain percentage, this is useful when the user doesn't want to do a full scan of all the log, but just ping it to see if there is some problem...
- attack: Specify what classes of vulnerabilities the tool will look at (eg, look only for XSS, SQL Injection, etc.)
Example of utilization:

    ./scalp-0.4.py -l /var/log/httpd_log -f ./default_filter.xml -o ./scalp-output --html

### Help

    rgaucher@plop:~/work/scalp/branches$ ./scalp-0.4.py --help

### Features
Since the main engine is done, I am currently focusing on the speed; for now, I am around 250000 lines of log in 170 seconds (which I consider not good, but okay compared to the Python's version I did before starting this one in C++) if I don't select an exhaustive list of the attacks (which means, it will not perform all the attack checking but stop at the first found -- based on criteria which is IMPACT > TYPE). To increase the speed, I am looking to use a multi-thread engine in order to take advantage of the muti-core processors.

Beside the speed of this software, a couple of points are important:

- output in many formats (TEXT, XML, HTML)
- options in order to let the user do a pre-selection (mainly with a range of dates)
- configuration of the format of the Apache log may come later...
