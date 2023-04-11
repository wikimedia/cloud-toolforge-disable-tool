-- SPDX-License-Identifier: Apache-2.0

CREATE TABLE `toolstate` (
   `toolname` varchar(255),
   `grid_disabled` tinyint(4) DEFAULT 0,
   `kubernetes_disabled` tinyint(4) DEFAULT 0,
   `db_disabled` tinyint(4) DEFAULT 0,
   `crontab_disabled` tinyint(4) DEFAULT 0,
   `ldap_deleted` tinyint(4) DEFAULT 0,
   `dbuser_deleted` tinyint(4) DEFAULT 0,
   `home_archived` tinyint(4) DEFAULT 0,
   PRIMARY KEY (`toolname`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
