#
# Table structure for table 'tx_caretakerpasswordcracker_domain_model_user'
#
CREATE TABLE tx_caretakerpasswordcracker_domain_model_user (
	uid int(11) NOT NULL auto_increment,
	pid int(11) DEFAULT '0' NOT NULL,

	tstamp int(11) unsigned DEFAULT '0' NOT NULL,
	crdate int(11) unsigned DEFAULT '0' NOT NULL,
	cruser_id int(11) unsigned DEFAULT '0' NOT NULL,
	deleted tinyint(4) unsigned DEFAULT '0' NOT NULL,
	hidden tinyint(4) unsigned DEFAULT '0' NOT NULL,
	starttime int(11) unsigned DEFAULT '0' NOT NULL,
	endtime int(11) unsigned DEFAULT '0' NOT NULL,

	user_username varchar(255) DEFAULT '' NOT NULL,
	user_password varchar(255) DEFAULT '' NOT NULL,

	host varchar(255) DEFAULT '' NOT NULL,
	cracked tinyint(4) unsigned DEFAULT '0' NOT NULL,

	PRIMARY KEY (uid),
	KEY parent (pid),
);
