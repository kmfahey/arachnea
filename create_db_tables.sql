CREATE DATABASE arachnea;

CREATE TABLE `bad_instances` (
  `bad_instance_id` int NOT NULL AUTO_INCREMENT,
  `instance` varchar(255) NOT NULL,
  `issue` enum('malfunctioning','suspended','unparseable') DEFAULT NULL,
  PRIMARY KEY (`bad_instance_id`)
);

CREATE TABLE `deleted_users` (
  `handle_id` int NOT NULL,
  `username` varchar(255) NOT NULL,
  `instance` varchar(255) NOT NULL,
  PRIMARY KEY (`handle_id`)
);

CREATE TABLE `followers` (
  `profile_handle_id` int NOT NULL,
  `follower_handle_id` int NOT NULL,
  PRIMARY KEY (`profile_handle_id`)
);

CREATE TABLE `following` (
  `profile_handle_id` int NOT NULL,
  `following_handle_it` int NOT NULL,
  PRIMARY KEY (`profile_handle_id`)
);

CREATE TABLE `handles` (
  `handle_id` int NOT NULL AUTO_INCREMENT,
  `username` varchar(255) NOT NULL,
  `instance` varchar(255) NOT NULL,
  PRIMARY KEY (`handle_id`)
);

CREATE TABLE `profiles` (
  `profile_handle_id` int NOT NULL,
  `username` varchar(255) NOT NULL,
  `instance` varchar(255) NOT NULL,
  `considered` tinyint(1) NOT NULL,
  `profile_snippet` varchar(8192) NOT NULL,
  `updated` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`profile_handle_id`),
  FULLTEXT KEY `profile_snippet` (`profile_snippet`)
);

CREATE TABLE `relations` (
  `profile_handle_id` int NOT NULL,
  `profile_username` varchar(255) NOT NULL,
  `profile_instance` varchar(255) NOT NULL,
  `relation_handle_id` int NOT NULL,
  `relation_type` enum('following','followers') NOT NULL,
  `relation_page_number` int NOT NULL,
  `relation_username` varchar(255) NOT NULL,
  `relation_instance` varchar(255) NOT NULL,
  PRIMARY KEY (`profile_handle_id`,`relation_type`,`relation_username`,`relation_instance`)
);
