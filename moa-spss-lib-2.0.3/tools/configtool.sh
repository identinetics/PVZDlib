#!/bin/sh

#
# Script to invoke the ConfigTool class	
#
# Author: Gregor Karlinger
# Version: $Id:  $
#


if [ -z "$JAVA_HOME" ]; then 
  echo "error: JAVA_HOME not defined";
  exit;
fi

CONFIGTOOL=at.gv.egovernment.moa.spss.server.tools.ConfigTool
TOOLSPATH=`dirname $PWD/$0`
CLASSPATH=$TOOLSPATH/tools.jar:$TOOLSPATH/xalan.jar

$JAVA_HOME/bin/java -classpath $CLASSPATH $CONFIGTOOL $*
