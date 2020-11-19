#!/bin/sh

if [ $1 ] ; then
        python3 agenerator.py -name PLEASEINSERT $1

else
	echo "usage : ./generator.py [jsonfile]"
fi
