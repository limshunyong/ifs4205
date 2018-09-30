-- MySQL dump 10.13  Distrib 8.0.12, for macos10.13 (x86_64)
--
-- Host: ifs4205-t2-3-i.comp.nus.edu.sg    Database: ifs4205
-- ------------------------------------------------------
-- Server version	8.0.12

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
 SET NAMES utf8 ;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `Health_Data`
--

DROP TABLE IF EXISTS `Health_Data`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `Health_Data` (
  `Data_ID` int(11) NOT NULL,
  `Patient_ID` int(11) DEFAULT NULL,
  `Therapist_ID` int(11) DEFAULT NULL,
  `Category` varchar(45) DEFAULT NULL,
  `Health_Data_Type` varchar(45) DEFAULT NULL,
  `Name` varchar(255) DEFAULT NULL,
  `Date` datetime DEFAULT NULL,
  `Data` text,
  `Patient_Can_View` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`Data_ID`),
  KEY `Patient_ID_5_idx` (`Patient_ID`),
  KEY `Therapist_ID_4_idx` (`Therapist_ID`),
  CONSTRAINT `Patient_ID_5` FOREIGN KEY (`Patient_ID`) REFERENCES `Patient` (`patient_id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `Therapist_ID_4` FOREIGN KEY (`Therapist_ID`) REFERENCES `Therapist` (`therapist_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `Is_a_Patient_of`
--

DROP TABLE IF EXISTS `Is_a_Patient_of`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `Is_a_Patient_of` (
  `ID` int(11) NOT NULL,
  `Patient_ID` int(11) NOT NULL,
  `Therapist_ID` int(11) NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `Patient_ID_idx` (`Patient_ID`),
  KEY `Therapist_ID_idx` (`Therapist_ID`),
  CONSTRAINT `Patient_ID_1` FOREIGN KEY (`Patient_ID`) REFERENCES `Patient` (`patient_id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `Therapist_ID_1` FOREIGN KEY (`Therapist_ID`) REFERENCES `Therapist` (`therapist_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `Patient`
--

DROP TABLE IF EXISTS `Patient`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `Patient` (
  `Patient_ID` int(11) NOT NULL,
  `Patient_Name` varchar(255) DEFAULT NULL,
  `NRIC` varchar(9) DEFAULT NULL,
  `Gender` varchar(6) DEFAULT NULL,
  `Address` varchar(255) DEFAULT NULL,
  `Contact_Number` varchar(12) DEFAULT NULL,
  `Date_of_Birth` datetime DEFAULT NULL,
  PRIMARY KEY (`Patient_ID`),
  CONSTRAINT `Patient_ID` FOREIGN KEY (`Patient_ID`) REFERENCES `Patient_Account` (`patient_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `Patient_Account`
--

DROP TABLE IF EXISTS `Patient_Account`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `Patient_Account` (
  `Patient_ID` int(11) NOT NULL,
  `Username` varchar(45) DEFAULT NULL,
  `Password` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`Patient_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `Therapist`
--

DROP TABLE IF EXISTS `Therapist`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `Therapist` (
  `Therapist_ID` int(11) NOT NULL,
  `Therapist_Name` varchar(255) DEFAULT NULL,
  `Designation` varchar(45) DEFAULT NULL,
  `Department` varchar(45) DEFAULT NULL,
  `Contact_Number` varchar(12) DEFAULT NULL,
  PRIMARY KEY (`Therapist_ID`),
  CONSTRAINT `Therapist_ID` FOREIGN KEY (`Therapist_ID`) REFERENCES `Therapist_Account` (`therapist_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `Therapist_Account`
--

DROP TABLE IF EXISTS `Therapist_Account`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `Therapist_Account` (
  `Therapist_ID` int(11) NOT NULL,
  `Username` varchar(45) DEFAULT NULL,
  `Password` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`Therapist_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `Visit_Record`
--

DROP TABLE IF EXISTS `Visit_Record`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `Visit_Record` (
  `Visit_ID` int(11) NOT NULL,
  `Patient_ID` int(11) NOT NULL,
  `Therapist_ID` int(11) NOT NULL,
  `Visit_Date` datetime DEFAULT NULL,
  PRIMARY KEY (`Visit_ID`),
  KEY `Patient_ID_3_idx` (`Patient_ID`),
  KEY `Therapist_ID_2_idx` (`Therapist_ID`),
  CONSTRAINT `Patient_ID_3` FOREIGN KEY (`Patient_ID`) REFERENCES `Patient` (`patient_id`) ON DELETE CASCADE ON UPDATE CASCADE,
  CONSTRAINT `Therapist_ID_2` FOREIGN KEY (`Therapist_ID`) REFERENCES `Therapist` (`therapist_id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `Ward`
--

DROP TABLE IF EXISTS `Ward`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `Ward` (
  `Ward_ID` int(11) NOT NULL,
  `Ward_Name` varchar(45) DEFAULT NULL,
  PRIMARY KEY (`Ward_ID`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `Ward_Has_Person`
--

DROP TABLE IF EXISTS `Ward_Has_Person`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
 SET character_set_client = utf8mb4 ;
CREATE TABLE `Ward_Has_Person` (
  `ID` int(11) NOT NULL,
  `Ward_ID` int(11) DEFAULT NULL,
  `Person_ID` varchar(36) NOT NULL,
  PRIMARY KEY (`ID`),
  KEY `Ward_ID_idx` (`Ward_ID`),
  CONSTRAINT `Ward_ID` FOREIGN KEY (`Ward_ID`) REFERENCES `Ward` (`ward_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping events for database 'ifs4205'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2018-09-27 12:40:44
