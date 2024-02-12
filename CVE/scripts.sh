#!/bin/bash
# LICENCE GPL
dest="/var/opt"
fichier="$dest/cve"
annee=$(date +%Y)
emaile="un@email.fr"
mdp="hgfdytrtezagx"
emaild="deux@email.fr"
cvedetails="cvedetails.com"
fichcve="listecve.txt"
opencve="opencve.io"
tomcat="tomcat"
pgsql="postgresql"
apache="apache"
tete="$fichier.entete"
corps="$fichier.corps"
body="$fichier.body"
smtp="smtps://smtp.email.fr:465/"

touch $corps $body $tete

entete(){
echo "Date: $(date)" > $tete
echo "To: $emaild" >> $tete
echo "From: $emaile" >> $tete
echo "Subject: Nouvelle CVE pour $sujet" >> $tete
echo "" >> $tete
cat /tmp/.entete > $body
cat $corps >> $body
rm -rf $corps
}

mail(){
curl -s \
    --url "$smtp" \
    --user "$emaile:$mdp" \
    --mail-from "$emaile" \
    --mail-rcpt "$emaild" \
    --upload-file $body
rm -rf $tete $body
}

# Boucles
IFS=$'\n'
for http in $(cat $fichcve);
do
if [ "$cvedetails" == "$(echo $http | cut -c 13- | awk -F'/' '{print $1}')" ]; then
 quoi=$(echo $http | awk -F"/" '{print $NF}' | awk -F"." '{print $1}')
 curl -k -v "$http" | tee "$fichier$quoi.curl"
 sed -n -e '/<table class="searchresults sortable" id="vulnslisttable">/,/<\/table>/ p' "$fichier$quoi.curl" | tee "$fichier$quoi.sed"
 cp "$fichier$quoi.sed" "$fichier$quoi.sed.html"
 lynx -dump "$fichier$quoi.sed.html" | tee "$fichier$quoi.lynx"

 # debut fichier final :
 echo "        ---" | tee "$fichier$quoi.fin"
 echo ":::::::::::: $quoi :::::::::::::::" | tee -a "$fichier$quoi.fin"
 echo "" | tee -a "$fichier$quoi.fin"
 echo "Numero         ::: Note ::: Date       ::: Modif      :::" | tee -a "$fichier$quoi.fin"

  for i in 1 2 3;
  do
   plus=$((i+1))
   grep -A 2 "   $i " "$fichier$quoi.lynx" | tee "$fichier$quoi.un"
   numcve=$(cat "$fichier$quoi.un" | head -1| awk -F" " '{print $2}' | awk -F"]" '{print $2}')
   ncve=$(cat "$fichier$quoi.un" | head -1| awk -F" " '{print $3}')
   typecve=$(cat "$fichier$quoi.un" | head -1| awk -F" " '{print $4}')
   datecve=$(cat "$fichier$quoi.un" | head -1| awk -F" " '{print $5}')
   modifcve=$(cat "$fichier$quoi.un" | head -1| awk -F" " '{print $6}')
   critcve=$(cat "$fichier$quoi.un"| sed -e '1d' -e '3d' | awk -F" " '{print $1}')
   corpscve=$(sed -n -e "/   $i /,/   $plus / p" "$fichier$quoi.lynx" | sed -e '1,3d' -e '$d')
   complcve=$(sed -n -e "/   $i /,/   $plus / p" "$fichier$quoi.lynx" | sed -e '1,2d' -e '4,$d')
   echo "$numcve ::: $critcve  ::: $datecve ::: $modifcve :::" | tee -a "$fichier$quoi.fin"
   echo "$corpscve" | tee -a "$fichier$quoi.fin"
   echo "Gained Access Level - Access Complexity - Authentication - Conf. - Integ. - Avail." | tee -a "$fichier$quoi.fin"
   echo "-->> $complcve" | tee -a "$fichier$quoi.fin"
   echo ""| tee -a "$fichier$quoi.fin"
   echo "Liens :"| tee -a "$fichier$quoi.fin"
   echo "* https://cve.mitre.org/cgi-bin/cvename.cgi?name=$numcve (MITRE)" | tee -a "$fichier$quoi.fin"
   echo "* https://www.cvedetails.com/cve/$numcve/ (CVEDETAILS)" | tee -a "$fichier$quoi.fin"
   echo "* https://www.opencve.io/cve/$numcve  (OPENVCE)" | tee -a "$fichier$quoi.fin"
   echo "* https://nvd.nist.gov/vuln/detail/$numcve (NIST)" | tee -a "$fichier$quoi.fin"
   echo ""| tee -a "$fichier$quoi.fin"
  done

 cp -a "$fichier$quoi.fin" "$corps"

 if [ "$(cat \"$dest/$quoi.pre\")" == "$(cat \"$fichier$quoi.fin\")" ];
 then
  echo ""
  sleep 10
 else
  sujet="$quoi"
  entete
  mail
  sleep 10
 fi
#cat $fichier$quoi.fin | mail -s "Nouveau CVE pour $quoi" -r $emaile $emaild

 mv "$dest/$quoi.pre" "$dest/$quoi.pre.old"
 cp -a "$fichier$quoi.fin" "$dest/$quoi.pre"
 rm -rf "$fichier*"

elif [ "$opencve" == "$(echo $http | cut -c 13- | awk -F'/' '{print $1}')" ]; then
  echo ""
elif [ "$tomcat" == "$(echo $http | cut -c 9- | awk -F'.' '{print $1}')" ]; then
 lynx -dump "$http" > $fichier$tomcat.0.txt
 nouveau=$(cat $fichier$tomcat.0.txt | grep "]Fixed in Apache Tomcat 8" | head -n1 | awk -F"]" '{print $2}')
 sed -n -e "/ $nouveau/,/Affects/ p" $fichier$tomcat.0.txt | tee $fichier$tomcat.1.txt
 sed -e 's/\[[0-9]*\]//g' $fichier$tomcat.1.txt > $fichier$tomcat.txt

 cp -a "$fichier$tomcat.txt" "$corps"

 if [ "$(cat \"$dest/$tomcat.txt\")" == "$(cat \"$fichier$tomcat.txt\")" ]; then
  echo "rien"
  sleep 10
 else
  sujet="$tomcat"
  entete
  mail
  sleep 10
 fi
#  cat $fichier$tomcat.1.txt | mail -s "Nouveau CVE pour $tomcat" -r $emaile $emaild

 cp -a $dest/$tomcat.txt $dest/$tomcat.txt.old
 mv -f $fichier$tomcat.txt $dest/$tomcat.txt
 rm -rf "$fichier*"

elif [ "$pgsql" == "$(echo $http | cut -c 13- | awk -F'.' '{print $1}')" ]; then
 lynx -dump $http > $fichier.pgsql1
 awk "/]CVE-/,/more details/" $fichier.pgsql1 > $fichier.pgsql2
 grep -v -E "]more|]Ann" $fichier.pgsql2 > $fichier.pgsql3
 sed -e 's/CVE/\n\nCVE/g' -e 's/\[[0-9]*\]//g' -e 's/:H /:H \n/g' -e 's/:N /:N \n/g' -e 's/   //g' $fichier.pgsql3 > $fichier.pgsql4
 echo $http > $fichier.pgsql
 cat $fichier.pgsql4 >> $fichier.pgsql

 cp -a "$fichier.pgsql" "$corps"

 if [ "$(cat \"$dest/$pgsql.txt\")" == "$(cat \"$fichier.pgsql\")" ]; then
  echo "rien"
  sleep 10
 else
  sujet="$pgsql"
  entete
  mail
  sleep 10
 fi
#  cat $fichier.pgsql | mail -s "Nouveau CVE pour $pgsql" -r $emaile $emaild

 mv -f $fichier.pgsql $dest/$pgsql.txt
 rm -rf "$fichier*"

elif [ "$apache" == "$(echo $http | cut -c 15- | awk -F'.' '{print $1}')" ]; then
 lynx -dump $http > $fichier.httpd1
 awk "/Fixed in Apache HTTP Server 2.4/,/Copyright/" $fichier.httpd1 > $fichier.httpd2
 sed -e 's/\[[0-9]*\]//g' $fichier.httpd2 > $fichier.httpd3
 echo $http > $fichier.httpd
 cat $fichier.httpd3 >> $fichier.httpd

 cp -a "$fichier.httpd" "$corps"

 if [ "$(cat \"$dest/$apache.txt\")" == "$(cat \"$fichier.httpd\")" ]; then
  echo "rien"
  sleep 10
 else
  sujet="$apache"
  entete
  mail
  sleep 10
 fi
#  cat $fichier.httpd | mail -s "Nouveau CVE pour $apache" -r $emaile $emaild

 mv -f $fichier.httpd $dest/$apache.txt
 rm -rf "$fichier*"

else
 continue
fi
done
