#!/usr/bin/env python
"""
File: sexr.py
Author: Don C. Weber
Start Date: 10052008
Purpose: Scalp External XML Reporter parses Scalp XML files and output
alert information, statistics, and detected IP addresses

Copyright 2008 Don C. Weber <cutaway@cutawaysecurity.com>

License:
This work is licensed under the Creative Commons Attribution-Share Alike 3.0 
United States License. To view a copy of this license, visit 
http://creativecommons.org/licenses/by-sa/3.0/us/ or send a letter to 
Creative Commons, 171 Second Street, Suite 300, San Francisco, California, 
94105, USA.


Last Mod: 12292008
Mods:
    12292008 - Removed some residual debugging messages.


Notes:
    No official DTD for Scalp XML scheme provided.
    DTD for Scalp XML scheme. NOTE: First time I have done this so it may or may not be correct.
----------------------
File: scalp_xmldtd.dtd

<!ELEMENT scalp (attack*)>
<!ATTLIST scalp         file    CDATA   #REQUIRED
                        time    CDATA   #REQUIRED>
<!ELEMENT attack (impact*)>
<!ATTLIST attack        type    CDATA   #REQUIRED
                        name    CDATA   #IMPLIED>
<!ELEMENT impact (item+)>
<!ATTLIST impact        value   CDATA   #REQUIRED>
<!ELEMENT item (reason, line)>
<!ELEMENT reason (#PCDATA )>
<!ELEMENT line (#PCDATA )>
 ----------------------

To Do:
    - Count hits by attack type
    - Count hits by attacking IP
    - Create CSV output - not sure if this is necessary, if so use "import csv" module

Resources: 
    Scalp: http://code.google.com/p/apache-scalp/
    PHP-IDS: http://php-ids.org/
    PyXML: http://pyxml.sourceforge.net
    DTD Attributes: http://www.w3schools.com/DTD/dtd_attributes.asp
    Declaring Attributes and Entities in DTDs: http://www.criticism.com/dita/dtd2.html
    Apache Log Format 1.3: http://httpd.apache.org/docs/1.3/logs.html
    Apache Log Format 2.2: http://httpd.apache.org/docs/2.2/logs.html
    The lxml.etree Tutorial: http://codespeak.net/lxml/tutorial.html
    Validation with lxml: http://codespeak.net/lxml/validation.html#dtd
    Dive in Python - Handling command line arguments: 
        http://www.faqs.org/docs/diveintopython/kgp_commandline.html
"""
import os
import sys
import datetime
import getopt
import glob

try:
    import psyco
    psyco.full()
except ImportError:
    print "%s: psyco is not installed" % sys.argv[0]
    pass

try:
    from lxml import etree
except ImportError:
    try:
        import xml.etree.cElementTree as etree
    except ImportError:
        try:
            import xml.etree.ElementTree as etree
        except ImportError:
            print "%s: Cannot find the ElementTree in your python packages" % sys.argv[0]

__application__ = "sexr"
__version__ = "0.1"
__release__ = __application__ + "/" + __version__
__author__ = "Don C. Weber"
__copyright__ = "Copyright 2008 Don C. Weber"
__license__ = "Creative Commons Attribution-Share Alike 3.0 United States License"
__credits__ = "Don C. Weber"
__maintainer__ = "Don C. Weber"
__email__ = "cutaway@cutawaysecurity.com"

def xparse(xml_file, val_dtd):
    """
    Function: xparse
    Variables: 
        xml_file - the XML file to be reviewed
        val_dtd - The DTD object for validation

    Return:
        On Success: Parsed XML 'Element'
        On Fail: Return nothing which basically skips the file
    
    Purpose:
        This function takes the xml_file and parses it into a handler
        so that it can be evaluated.
    """
    try:
        xml_handler = open(xml_file, 'r')
        xparse = etree.parse(xml_handler).getroot()
        if not val_dtd.validate(xparse):
            print "%s: XML file does not comply with Scalp DTD: %s" % (sys.argv[0], xml_file)
            return ""
        xml_handler.close()
        return xparse
    except IOError:
        print "%s: IOError with the filter's file: %s" % (sys.argv[0], xml_file)
        return
    except:
        print "%s: Unknown error with the filter's file: %s" % (sys.argv[0], xml_file)
        return ""
        

def iter(node,indent,fOUT):
    """
    Function: iter
    Variables: 
        node - the node of the XML tree to be evaluated
        indent - spaces for visual purposes only, helps build a visible tree for text
    
    Purpose:
        Iterate through a specific node of the XML tree.  First show the attributes
        and their values and then show any text for the node.  The check to see if 
        the node has any children and iterate through them.  Continue until complete.
    """

    len_node = len(node)
    indent += '   '
    if len(node.attrib):
        # print "%s%s: %s" % (indent, node.tag, node.attrib)
        line_out = "%s%s: %s\n" % (indent, node.tag, node.attrib)
        fOUT.write(line_out)
    else:
        # print indent + node.tag
        line_out = indent + node.tag + "\n"
        fOUT.write(line_out)
    if len(node.text.strip()):
        # print "%s - %s" % (indent, node.text)
        line_out = "%s - %s\n" % (indent, node.text)
        fOUT.write(line_out)
    if len_node:
        for ch in node:
            iter(ch,indent,fOUT)

def item_cnt_iter(node,indent,fOUT):
    """
    Function: item_cnt_iter
    Variables: 
        node - the node of the XML tree to be evaluated
        indent - spaces for visual purposes only, helps build a visible tree for text
    
    Purpose:
        Iterate through each node of the XML tree until it gets to the Impact node.
        When this node is encountered, count the number of source IP addresses that
        were associated with the flagged requests.  Each impact will have specific
        reasons an alert was triggered.  Count the number of alerts per reason.
    """

    len_node = len(node)
    indent += '   '
    d_impact = {}
    ip_impact = {}

    if node.tag == "impact":    # Analyze all impact nodes
        # print "%sImpact %s Items: %s" % (indent, node.get('value'), str(len(node)))
        line_out = "%sImpact %s Items: %s\n" % (indent, node.get('value'), str(len(node)))
        fOUT.write(line_out)
        d_impact.clear()
        for i_ch in node:   # loop through children of impact = items
            for ic_ch in i_ch:  # loop through children of items = reason,line,regexp
                if ic_ch.tag == "line" and _scan == "IP":
                    source_ip = ic_ch.text.split()  # Grab and count the IP from the flagged log entry
                    if ip_impact.has_key(source_ip[0]):
                        ip_impact[source_ip[0]] += 1
                    else:
                        ip_impact[source_ip[0]] = 1
                if ic_ch.tag == "reason" and _scan == "count":           # Grab and count the alert
                    if d_impact.has_key(ic_ch.text):
                        d_impact[ic_ch.text] += 1
                    else:
                        d_impact[ic_ch.text] = 1
        if len(d_impact) and _scan == "count":
            for key, value in d_impact.items():
                # print "%s - \'%s\': %s" % (indent, key, str(value))
                line_out = "%s - \'%s\': %s\n" % (indent, key, str(value))
                fOUT.write(line_out)
        if len(ip_impact) and _scan == "IP":
            # print "%s - Total Source IP Addresses: %s" % (indent, len(ip_impact))
            line_out = "%s - Total Source IP Addresses: %s\n" % (indent, len(ip_impact))
            fOUT.write(line_out)
            # Sort on keys only since values are not unique
            # I might try to figure this out later
            ip_addr = ip_impact.keys()
            ip_addr.sort()
            for addr in ip_addr:
                # print "%s - %s: %d" % (indent, addr, ip_impact[addr])
                line_out = "%s - %s: %s\n" % (indent, addr, ip_impact[addr])
                fOUT.write(line_out)
        return

    if len_node:
        if len(node.attrib):
            # print "%s%s: %s" % (indent, node.tag, node.attrib)
            line_out = "%s%s: %s\n" % (indent, node.tag, node.attrib)
            fOUT.write(line_out)
        else:
            # print indent + node.tag
            line_out = indent + node.tag + "\n"
            fOUT.write(line_out)
        if len(node.text.strip()):
            # print "%s - %s" % (indent, node.text)
            line_out = "%s - %s\n" % (indent, node.text)
            fOUT.write(line_out)
        for ch in node:
            item_cnt_iter(ch,indent,fOUT)
    else:
        return

def set_foutput(fOUT):
    """
    Function: set_foutput
    Variables: 
        fOUT - file handle for output
        none - all globals

    Purpose:
        Set new output file
    """
    outFile = "%s%s%s" % (_dout, _fout, _fout_ext)
    print "%s: Writing output to %s" % (sys.argv[0], outFile)
    try:
        fOUT = open(outFile, 'w')
    except IOError:
        print "%s: Error opening file location. Check permissions: %s" % (sys.argv[0], outFile)
        sys.exit(1)

    return fOUT

def help():
    """
    Function: help
    Variables: 
        None

    Purpose:
        Print help output to stdout
    """

    print "Scalp External XML Reporter"
    print "Author: Don C. Weber"
    print ""
    print "usage:   ./sexr.py [-h|--help] [-V|--version] [-v xml_dtd] [-d out_directory]"
    print "                   [-t | -f | -a | -s] <xml file or directory>"
    print ""
    print "    -h | --help:     Print this help."
    print "    -V | --version:  Version information."
    print "    -v:              The Scalp DTD file.  './scalp_xmldtd.dtd' by default."
    print "    -d:              The directory to write the output files. './' by default. Implies -t"
    print "    -t:              Text output.  This will produce a indented text file which"
    print "                     will be written to 'sexr_<date.time>.<##>.txt'."
    print "    -f:              Full parse to selected output format."
    print "    -a:              Provides a count of specific attacks detected to selected"
    print "                     output format."
    print "    -s:              Provides a count of the Source IP addresses associated with"
    print "                     the specific Attack types to selected output format."

def version():
    """
    Function: version
    Variables:
        None

    Purpose:
        Print version informatin out stdout
    """
    print "Scalp External XML Reporter release: %s" % __release__
    print "%s" % __copyright__
    print "%s" % __license__
    print ""
    print "Credits: %s" % __credits__
    

#def main(argv):
def main():
    """
    Function: main
    Variables:
        argv = List of command line arguments NOT including the program name.

    Purpose:
        The main function where the user's intent is determined and all of the 
        functions are called.
    """
    ###################
    # Init
    ###################

    # Setup variables and default locations
    global _dout        # Directory to write output
    global _fhandle
    global _fout        # File to write output
    global _fout_ext    # File extention in case Text, if STDOUT then this = "" which is default
    global _scan        # Scan type: full = full parse, count = count by attack type, IP = List Source IPs of attack
    _dout = os.getcwd() + "/"            # default write to current working directory
    _fhandle = sys.stdout  # Default output is to stdout
    _fout_ext = ""
    _scan = "full"      # Default
    dnow = datetime.datetime.utcnow()
    fnow = "%s.%s" % (dnow.date(), dnow.time())
    fdtd = "scalp_xmldtd.dtd"           # Default DTD file for validation
    vdtd = ""
    xdtd = ""

    # Grab file or directory 
    if len(sys.argv) < 2:
        help()
        sys.exit()
    if len(sys.argv) > 1:
        inXML = sys.argv.pop(len(sys.argv) - 1)

    # Get program options
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hVv:d:tfas",["help","version"])
    except getopt.GetoptError:
        # Program help
        print "%s: command line error" % sys.argv[0]
        help()
        sys.exit(1)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            help()
            sys.exit()
        elif opt in ("-V", "--version"):
            version()
            sys.exit()
        elif opt == ("-v"):     # Validation -  DTD file 
            fdtd = os.path.abspath(arg)
            if not os.path.isfile(fdtd):
                print "%s: Could not find DTD file: %s" % (sys.argv[0], fdtd)
                sys.exit(1)
        elif opt == ("-d"):     # Output directory
            # check for ending / and append if none
            _dout = os.path.abspath(arg)
            if not os.path.exists(_dout):
                try:
                    os.mkdir(_dout)
                except OSError:
                    print "%s: Could not create: %s" % (sys.argv[0], _dout)
            if not _dout[len(_dout) - 1] == "/":
                _dout = _dout + "/"
            # Set these again in case user forgot -t
            _fout = "sexr_%s." % fnow
            _fout_ext = ".txt"
        elif opt == ("-t"):     # Text output
            _fout = "sexr_%s." % fnow
            _fout_ext = ".txt"
        elif opt == ("-f"):     # Full Parse - default
            _scan = "full"
        elif opt == ("-a"):    # count by attack type
            _scan = "count"
        elif opt == ("-s"):    # List Source IPs of attack
            _scan = "IP"
        else:
            print "%s: Detected unrecognized command line argument." % sys.argv[0]
            help()
            sys.exit(1)

    # validate Scalp XML files
    tempXML = []
    if os.path.isdir(inXML):
        tempXML = glob.glob(os.path.abspath(inXML + '/*'))
        for fXML in tempXML:
            if os.path.isdir(fXML):
                tempXML.pop(tempXML.index(fXML))
    elif os.path.isfile(inXML):
        tempXML.insert(0,os.path.abspath(inXML))
    else:
        print "%s: Could not find Scalp XML file." % sys.argv[0]
        help()
        sys.exit(1)
    inXML = []          # convert inXML to a list
    inXML = tempXML

    # Prep for XML validation
    if not os.path.isfile(fdtd):
        print "%s: Could not find DTD file: %s" % (sys.argv[0], fdtd)
        sys.exit(1)
    try:
        xdtd = open(fdtd,'r')
    except:
        print "%s: Could not open DTD file: %s" % (sys.argv[0], fdtd)
        sys.exit(1)
    vdtd = etree.DTD(xdtd)
    

    ###################
    # Main
    ###################

    if _scan == "full":
        print "%s: Conducting %s scan of %s files" % (sys.argv[0], _scan, len(inXML))

        for fXML in inXML:
            # Parse the XML file and find the root node
            p_scalp = xparse(fXML, vdtd)
            len_p_scalp = len(p_scalp)
            if len_p_scalp < 1:     # Nothing found in file
                continue            # skip to next file
            
            # Determine where to write
            if len(_fout_ext):      # User wants output to file
                _fhandle = set_foutput(_fhandle)

            # Iterate through the whole XML file and print it to STDOUT
            iter(p_scalp,'',_fhandle)
            if len(_fout_ext):      # User wants output to file
                _fhandle.close()

    if _scan == "count" or _scan == "IP":
        print "%s: Conducting %s scan of %s files" % (sys.argv[0], _scan, len(inXML))

        for fXML in inXML:
            # Parse the XML file and find the root node
            p_scalp = xparse(fXML, vdtd)
            len_p_scalp = len(p_scalp)
            if len_p_scalp < 1:     # Nothing found in file
                continue            # skip to next file

            # Determine where to write
            if len(_fout_ext):      # User wants output to file
                _fhandle = set_foutput(_fhandle)

            # Iterate through the whole XML file but only show attack numbers
            # and source IP addresses
            item_cnt_iter(p_scalp,'',_fhandle)
            if len(_fout_ext):      # User wants output to file
                _fhandle.close()


    ###################
    # Clean up
    ###################

    print "%s: Done" % sys.argv[0]
    sys.exit()  # return


if __name__ == '__main__':

    # Function where all the work is done
    main()
