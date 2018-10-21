import lxml.etree
from xml_compare import xml_compare
import os

t1 = lxml.etree.parse('testdata/idp_valid_unsigned.xml')
t2 = lxml.etree.parse('testdata/idp_valid_unsigned_c14n.xml')
xml_compare(t1, t2)
