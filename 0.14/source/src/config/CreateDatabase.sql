-- This file is part of openGalaxy.
--
-- opengalaxy - a SIA receiver for Galaxy security control panels.
-- Copyright (C) 2015 - 2016 Alexander Bruines <alexander.bruines@gmail.com>
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License version 2 as
-- as published by the Free Software Foundation, or (at your option)
-- any later version.
--
-- In addition, as a special exception, the author of this program
-- gives permission to link the code of its release with the OpenSSL
-- project's "OpenSSL" library (or with modified versions of it that
-- use the same license as the "OpenSSL" library), and distribute the
-- linked executables. You must obey the GNU General Public License
-- in all respects for all of the code used other than "OpenSSL".
-- If you modify this file, you may extend this exception to your
-- version of the file, but you are not obligated to do so.
-- If you do not wish to do so, delete this exception statement
-- from your version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.
--

--
-- This file may be used to create the initial database for openGalaxy's MySQL output plugin
-- use: mysql -u root -p -h servername <CreateDatabase.sql
--

SET NAMES 'utf8';

DROP DATABASE IF EXISTS `Galaxy`;

CREATE DATABASE IF NOT EXISTS `Galaxy`;

USE `Galaxy`;

CREATE TABLE IF NOT EXISTS `SIA-Messages` (
 `id`                       BIGINT(1) UNSIGNED NOT NULL auto_increment, -- ID van de tabel row (set automaticly on insert)
 `AccountID`                INT(1)    UNSIGNED NOT NULL DEFAULT '0',    -- sia.AccountID             |
 `EventCode`                CHAR(2)            NOT NULL DEFAULT '',     -- sia.Event.letter_code     +---> These enries are always present
 `EventName`                CHAR(80)           NOT NULL DEFAULT '',     -- sia.Event.name            |     but under certain circumstances
 `EventDesc`                CHAR(80)           NOT NULL DEFAULT '',     -- sia.Event.desc            |     may only contain 0 or an empty string
 `EventAddressType`         CHAR(24)           NOT NULL DEFAULT '',     -- sia.AddressType           |
 `EventAddressNumber`       INT(1)    UNSIGNED          DEFAULT NULL,   -- sia.AddressNumber     |
 `DateTime`                 DATETIME           NOT NULL DEFAULT 0,      -- Date and time from the|SIA message or the receivers date/time if not available
 `ASCII`                    CHAR(64)                    DEFAULT NULL,   -- sia.ASCII             |
 `SubscriberID`             INT(1)    UNSIGNED          DEFAULT NULL,   -- sia.SubscriberID      |
 `AreaID`                   INT(1)    UNSIGNED          DEFAULT NULL,   -- sia.AreaID            |
 `PeripheralID`             INT(1)    UNSIGNED          DEFAULT NULL,   -- sia.PeripheralID      +---> If any of these entries is NULL,
 `AutomatedID`              INT(1)    UNSIGNED          DEFAULT NULL,   -- sia.AutomatedID       |     than that entry was not present
 `TelephoneID`              INT(1)    UNSIGNED          DEFAULT NULL,   -- sia.TelephoneID       |     in the SIA message...
 `Level`                    INT(1)    UNSIGNED          DEFAULT NULL,   -- sia.Level             |
 `Value`                    INT(1)    UNSIGNED          DEFAULT NULL,   -- sia.Value             |
 `Path`                     INT(1)    UNSIGNED          DEFAULT NULL,   -- sia.Path              |
 `RouteGroup`               INT(1)    UNSIGNED          DEFAULT NULL,   -- sia.RouteGroup        |
 `SubSubscriber`            INT(1)    UNSIGNED          DEFAULT NULL,   -- sia.SubSubscriber     |
 `raw`                      CHAR(64)                    DEFAULT NULL,   -- sia.raw.data[]
 `timeindex`                DATETIME           NOT NULL DEFAULT 0,      -- The date/time this message was logged (set automaticly on insert)
 PRIMARY KEY (`id`)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

CREATE TRIGGER set_timeindex BEFORE INSERT ON `SIA-Messages`
FOR EACH ROW SET NEW.timeindex = NOW();

-- CREATE TRIGGER sum_inserts AFTER INSERT ON `SIA-Messages`
-- FOR EACH ROW SET @new_inserts = @new_inserts + 1;
-- SET @new_inserts = 0;

--
-- The following is used by the MySQL useage demo in the /example directory
-- It may safely be deleted, when the example is not used.
--

CREATE TABLE IF NOT EXISTS `jqui_themes` ( `jqui_theme` CHAR(16) )
 ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

INSERT INTO `jqui_themes` VALUES ('black-tie'), ('blitzer'), ('cupertino'),
 ('dark-hive'), ('dot-luv'), ('eggplant'), ('excite-bike'), ('flick'),
 ('hot-sneaks'), ('humanity'), ('le-frog'), ('mint-choc'), ('overcast'),
 ('pepper-grinder'), ('redmond'), ('smoothness'), ('south-street'), ('start'),
 ('sunny'), ('swanky-purse'), ('trontastic'), ('ui-darkness'), ('ui-lightness'),
 ('vader' );


CREATE TABLE IF NOT EXISTS `GMS Settings` (
 `jqui_theme`               CHAR(16)
) ENGINE=MyISAM  DEFAULT CHARSET=utf8 COLLATE=utf8_general_ci;

INSERT INTO `GMS Settings` VALUES ( 'smoothness' );

