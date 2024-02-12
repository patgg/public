**Ce script permet de recevoir un message mail lors de nouveaux CVE.**

Il est prévu avec un usage de cvedetails et quelques autres logiciels specifiques comme tomcat, apache2 et postgresql.

Prérequis à l'usage du script :

* installation de curl et lynx
* dans le fichier listecve.txt, indiquez les liens cvedetails des CVE logiciels que vous surveillez
* dans script.sh, modifiez les valeurs des variables suivantes :
  * dest= : dossier où seront posés les fichiers temporaires (ex : /var/opt )
  * emaile= : email emetteur (ex : test@test.com )
  * mdp= : le mot de passe de l'email emetteur (ex : motdepassetressecret )
  * smtp= : adresse et protocole du serveur de mail qui enverra le message (ex : smtps://smtp.email.fr:465/ )
  * emaild= : email de destination (ex : test@test.com )
  * fichcve= : nom du fichier recensant les liens à analyser ( ex : listcve.txt )

lancement :
* bash script.sh
* ou dans un crontab : 0 0 * * * /bin/bash /path/du/script.sh
