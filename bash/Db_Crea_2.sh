#!/bin/bash


sudo mariadb <<< "DROP DATABASE IF EXISTS TEST; CREATE DATABASE TEST; USE TEST; CREATE TABLE etudiant(EtuID int NOT NULL AUTO_INCREMENT, nom varchar(12), annee int, foto BLOB, PRIMARY KEY (EtuID));" 
sudo mariadb <<< "DROP USER IF EXISTS gigachad; CREATE USER 'gigachad'@'%' IDENTIFIED BY 'mdp'; GRANT ALL ON TEST.* to 'gigachad'@'%' WITH GRANT OPTION;FLUSH PRIVILEGES;"
mariadb -u gigachad -p <<< "USE TEST; INSERT INTO etudiant (nom,annee,foto) VALUES ('Toto',2003,NULL),('Bico',2003,NULL),('Tata',2002,NULL);"
mariadb -u gigachad -p <<< "USE TEST; SELECT * FROM etudiant;"
