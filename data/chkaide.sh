#! /bin/bash

MYDATE=$(date +%Y-%m-%dT%H:%M:%S%z)
MYFILENAME="Aide-"$MYDATE.txt
echo "Aide check !! `date`\n\n" > /tmp/$MYFILENAME
aide --check > /tmp/$MYFILENAME
# mail -s"$MYFILENAME `date`" frankjtursi@gmail.com < /tmp/$MYFILENAME
