<?php
$extensionPath = t3lib_extMgm::extPath('caretaker_password_cracker');
return array(
	'tx_caretakerpasswordcracker_findinsecurebackendusertestservice' => $extensionPath . 'services/class.tx_caretakerpasswordcracker_FindInsecureBackendUserTestService.php',
	'tx_caretakerpasswordcracker_task_johnadapter' => $extensionPath . 'Classes/Task/JohnAdapter.php',
);
?>