CREATE TABLE `tblAuthSessions` (
  `intAuthID` int(11) NOT NULL AUTO_INCREMENT,
  `txtSessionKey` varchar(255) DEFAULT NULL,
  `dtExpires` datetime DEFAULT NULL,
  `txtRedir` varchar(255) DEFAULT NULL,
  `txtRefreshToken` text DEFAULT NULL,
  `txtCodeVerifier` varchar(255) DEFAULT NULL,
  `txtToken` text DEFAULT NULL,
  `txtIDToken` text DEFAULT NULL,
  PRIMARY KEY (`intAuthID`)
) ENGINE=InnoDB AUTO_INCREMENT=73 DEFAULT CHARSET=utf8mb4;
