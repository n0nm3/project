#!/bin/bash


sudo mariadb <<< "DROP DATABASE IF EXISTS TEST;CREATE DATABASE TEST; USE TEST; CREATE TABLE toto(EtuID int NOT NULL AUTO_INCREMENT primary key, nom varchar(12), prenom varchar(40), foto BLOB);" 
sudo mariadb <<< "DROP USER IF EXISTS gigachad; CREATE USER 'gigachad'@'%' IDENTIFIED BY 'mdp'; GRANT ALL ON TEST.* to 'gigachad'@'%' WITH GRANT OPTION;FLUSH PRIVILEGES;"
mariadb -u gigachad -p <<< "USE TEST; INSERT INTO toto (nom,prenom,foto) VALUES ('Toto','Bozo',NULL),('Bico','Moineau',NULL),('Tata','Cata',NULL);"
mariadb -u gigachad -p <<< "USE TEST; SELECT * FROM toto;"
