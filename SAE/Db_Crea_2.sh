#!/bin/bash


sudo mariadb <<< "DROP DATABASE IF EXISTS Dossier;CREATE DATABASE Dossier; USE Dossier; CREATE TABLE etudiant(EtuID int NOT NULL AUTO_INCREMENT, nom varchar(20), prenom varchar(40), picture BLOB, PRIMARY KEY (EtuID)); CREATE TABLE Math(EtuID int, Moyenne int, Prof varchar(20),FOREIGN KEY (EtuID) REFERENCES etudiant(EtuID));CREATE TABLE Anglais(EtuID int, Moyenne int, Prof varchar(20), FOREIGN KEY (EtuID) REFERENCES etudiant(EtuID)); CREATE TABLE Programmation(EtuID int, Moyenne int, Prof varchar(20), FOREIGN KEY (EtuID) REFERENCES etudiant(EtuID));" 

sudo mariadb <<< "DROP USER IF EXISTS gigachad; CREATE USER 'gigachad'@'%' IDENTIFIED BY 'mdp'; GRANT ALL ON TEST.* to 'gigachad'@'%' WITH GRANT OPTION;FLUSH PRIVILEGES;"

mariadb -u gigachad -p <<< "USE TEST; INSERT INTO etudiant (nom,prenom,foto) VALUES ('Toto','Bozo',NULL),('Bico','Moineau',NULL),('Tata','Cata',NULL); INSERT INTO matiere(EtuID,Math) VALUES(1,'45,4');"

mariadb -u gigachad -p <<< "USE TEST; SELECT * FROM etudiant;"
