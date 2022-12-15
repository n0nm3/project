#!/bin/bash


sudo mariadb <<< "CREATE DATABASE TEST; USE TEST; CREATE TABLE toto(test1 int, test2 varchar(12));" 
sudo mariadb <<< "CREATE USER user IDENTIFIED BY 'mdp'; GRANT ALL ON TEST.* to 'user@localhost';"
mariadb -u user -p <<< "USE TEST; INSERT INTO toto (nom,prenom,foto) VALUES ('Toto','Bozo',NULL),('Bico','Moineau',NULL),('Tata','Cata',NULL);"
mariadb -u user -p <<< "USE TEST; SELECT * FROM toto;"
