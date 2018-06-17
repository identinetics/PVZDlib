#!/bin/sh

#
# Script to invoke the CertTool class	
#
# Author:Patrick Peck
# Version: $Id: certtool.sh,v 1.9 2003/06/23 16:01:27 peck Exp $
#


if [ -z "$JAVA_HOME" ]; then 
  echo "error: JAVA_HOME not defined";
  exit;
fi

CERTOOL=at.gv.egovernment.moa.spss.server.tools.CertTool
TOOLSPATH=`dirname $PWD/$0`
CLASSPATH=$TOOLSPATH/tools.jar:$TOOLSPATH/iaik_moa.jar:$TOOLSPATH/iaik_jce_full.jar:$TOOLSPATH/iaik_ecc.jar:$TOOLSPATH/log4j.jar

$JAVA_HOME/bin/java -classpath $CLASSPATH $CERTOOL $*
