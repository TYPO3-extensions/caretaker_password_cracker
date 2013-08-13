<?php
if (!defined ('TYPO3_MODE')) {
	die('Access denied.');
}
if (t3lib_extMgm::isLoaded('caretaker') ) {
	tx_caretaker_ServiceHelper::registerCaretakerService(
		$_EXTKEY,
		'services',
		'tx_caretakerpasswordcracker_FindInsecureBackendUser',
		'ENET -> Find insecure backend user passwords',
		'Update local database of passwords and fail if a password has been cracked'
	);
}
?>