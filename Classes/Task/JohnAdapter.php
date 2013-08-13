<?php
/***************************************************************
 * Copyright notice
 *
 * (c) 2012 Christian Kuhn <lolli@schwarzbu.ch>
 *
 * All rights reserved
 *
 * This script is part of the Caretaker project. The Caretaker project
 * is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * The GNU General Public License can be found at
 * http://www.gnu.org/copyleft/gpl.html.
 *
 * This script is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * This copyright notice MUST APPEAR in all copies of the script!
 ***************************************************************/

/**
 * Manage password lists and john processes
 *
 * @author Chritian Kuhn <lolli@schwarzbu.ch>
 */
class Tx_CaretakerPasswordCracker_Task_JohnAdapter extends tx_scheduler_Task {

	/**
	 * @var string John executable location
	 */
	protected $johnExecutable = '';

	/**
	 * @var string Default john file location directory
	 */
	protected $johnDirectory = '';

	/**
	 * @var string Generic john cracking options
	 */
	protected $genericJohnOptions = '';

	/**
	 * @var array Hash methods and john options
	 */
	protected $hashMethodsWithJohnOptions = array();

	/**
	 * Execute task
	 *
	 * @return bool TRUE on success
	 * @throws Exception if something went wrong
	 */
	public function execute() {
		$success = TRUE;

		// @TODO: This is hardcoded path ... *this* one should be settable via task option
		$this->johnExecutable = '/var/www/foo/vhosts/caretaker/john/john/run/john';

		$this->hashMethodsWithJohnOptions = array(
			'md5' => '--format=raw-md5',
			'tx_saltedpasswords_salts_md5' => '',
			'tx_saltedpasswords_salts_blowfish' => '',
			'tx_saltedpasswords_salts_phpass' => '',
		);

		$this->johnDirectory = realpath(PATH_site . '../john/') . '/';
		if (!mb_strlen($this->johnDirectory) > 0 || !is_writable($this->johnDirectory)) {
			throw new Exception('john directory not writable', 1354891641);
		}
		if (!is_writable($this->johnDirectory . 'passwordLists/')) {
			throw new Exception('john password list directory not writable', 1354891642);
		}
		if (!is_writable($this->johnDirectory . 'sessions/')) {
			throw new Exception('john session directory not writable', 1354891643);
		}
		if (!is_writable($this->johnDirectory . 'wordlists/')) {
			throw new Exception('john wordlists directory not writable', 1354891643);
		}

//		$this->genericJohnOptions = '-wordlist:' . $this->johnDirectory . 'wordlists/combined.txt';

		// Re-create password lists if needed
		/** @var $registry t3lib_Registry */
		$registry = t3lib_div::makeInstance('t3lib_Registry');
		$recreateLists = $registry->get('tx_caretaker_password_cracker', 'changedPasswordData', FALSE);
		if ($recreateLists) {
			$this->createPasswordLists();
			$registry->set('tx_caretaker_password_cracker', 'changedPasswordData', FALSE);
			$this->stopPossibleRunningJohnProcesses();
		}

		$this->startJohnProcessesIfNotRunningAndNeeded();

		$this->markCrackedPasswordsAsCrackedInDatabase();

		return $success;
	}

	/**
	 * Get john status and mark password as cracked in database
	 *
	 * @return void
	 */
	protected function markCrackedPasswordsAsCrackedInDatabase() {
		foreach ($this->hashMethodsWithJohnOptions as $hashMethod => $johnOptions) {
			$passwordFile = $this->getAbsolutePasswordListFileLocationFromHashMethod($hashMethod);
			if (@is_file($passwordFile)) {
				$command = array();
				$command[] = $this->johnExecutable;
				$command[] = '--show';
				$command[] = $johnOptions;
				$command[] = $passwordFile;
				$showString = shell_exec(implode(' ', $command));
				$resultArray = explode(LF, $showString);
				foreach ($resultArray as $resultLine) {
					list($hostAndUser, $password) = explode(':', $resultLine);
					if (strlen($hostAndUser) > 0 && strlen($password) > 0) {
						$hostAndUserArray = explode('%', $hostAndUser);
						$host = '';
						$user = '';
						if (count($hostAndUserArray) === 2) {
							$host = $hostAndUserArray[0];
							$user = $hostAndUserArray[1];
						}
						if (strlen($host) > 0 && strlen($user) > 0) {
							$this->markHostUserCombinationAsCrackedInDatabase($host, $user);
						}
					}
				}
			}
		}
	}

	/**
	 * Mark a specific host and user comination as cracked in database
	 *
	 * @param string $host
	 * @param string $user
	 */
	protected function markHostUserCombinationAsCrackedInDatabase($host, $user) {
		$rows = $this->getDatabase()->exec_SELECTgetRows(
			'uid,cracked',
			'tx_caretakerpasswordcracker_domain_model_user',
			'host=' . $this->getDatabase()->fullQuoteStr($host, 'tx_caretakerpasswordcracker_domain_model_user') .
				' AND user_username=' . $this->getDatabase()->fullQuoteStr($user, 'tx_caretakerpasswordcracker_domain_model_user')
		);
		if (is_array($rows) && count($rows) === 1 && $rows[0]['cracked'] == 0) {
			$this->getDatabase()->exec_UPDATEquery(
				'tx_caretakerpasswordcracker_domain_model_user',
				'uid=' . (int)$rows[0]['uid'],
				array(
					'cracked' => 1,
				)
			);
		}
	}

	/**
	 * Check john processes and start if not running already
	 *
	 * @return void
	 */
	protected function startJohnProcessesIfNotRunningAndNeeded() {
		/** @var $registry t3lib_Registry */
		$registry = t3lib_div::makeInstance('t3lib_Registry');

		foreach ($this->hashMethodsWithJohnOptions as $hashMethod => $johnOptions) {
			// First check if there is a password file, if not, the process does not need to run
			if (@is_file($this->getAbsolutePasswordListFileLocationFromHashMethod($hashMethod))) {
				$processId = (int)$registry->get('tx_caretaker_password_cracker', 'johnProcess-' . $hashMethod, NULL);
				if (!$processId || !$this->testProcessIdIsARunningJohnProcess($processId)) {
					$this->startJohnProcessForHashMethod($hashMethod);
				}
			}
		}
	}

	/**
	 * Start a specific john process
	 *
	 * @param string $hashMethod
	 * @return void
	 */
	protected function startJohnProcessForHashMethod($hashMethod) {
		$command = array();
		$command[] = $this->johnExecutable;
		$command[] = $this->genericJohnOptions;

		$sessionFile = $this->getAbsoluteSessionFileLocationFromHashMethod($hashMethod);
		$command[] = '-session:' . $sessionFile;
		$command[] = $this->hashMethodsWithJohnOptions[$hashMethod];
		$command[] = $this->getAbsolutePasswordListFileLocationFromHashMethod($hashMethod);

		$command[] = '> /dev/null 2>&1 & echo $!';
		$command = implode(' ', $command);
		$return = array();
		exec($command, $return);
		$pid = $return[0];

		/** @var $registry t3lib_Registry */
		$registry = t3lib_div::makeInstance('t3lib_Registry');
		$registry->set('tx_caretaker_password_cracker', 'johnProcess-' . $hashMethod, $pid);
	}

	/**
	 * Stop all running john processes
	 *
	 * @throws Exception
	 * @return void
	 */
	protected function stopPossibleRunningJohnProcesses() {
		$hashMethods = array_keys($this->hashMethodsWithJohnOptions);

		/** @var $registry t3lib_Registry */
		$registry = t3lib_div::makeInstance('t3lib_Registry');

		foreach ($hashMethods as $hashMethod) {
			$processId = (int)$registry->get('tx_caretaker_password_cracker', 'johnProcess-' . $hashMethod, NULL);
			if ($processId) {
				if ($this->testProcessIdIsARunningJohnProcess($processId)) {
					if (!$this->sendSigIntToProcess($processId)) {
						throw new Exception('Unable to kill john process', 1354900791);
					}
				}
				$registry->remove('tx_caretaker_password_cracker', 'johnProcess-' . $hashMethod);
			}
		}
		sleep(1);
	}

	/**
	 * Test that given process id is the id of a john process
	 *
	 * @param integer $id process id to test
	 * @return boolean TRUE if process is a running john
	 */
	protected function testProcessIdIsARunningJohnProcess($id) {
		$psString = shell_exec('/bin/ps ho comm ' . (int)$id);
		if (trim($psString) === 'john') {
			return TRUE;
		} else {
			return FALSE;
		}
	}

	/**
	 * Stop running john process
	 *
	 * @param integer $id
	 * @return boolean TRUE on success
	 */
	protected function sendSigIntToProcess($id) {
		// ubuntu does not compile in pcntl in not-cli, 2 = SIGINT, see http://de3.php.net/manual/de/pcntl.constants.php
		return posix_kill($id, 2);
	}

	/**
	 * Write out one password file per hash sytem
	 *
	 * @return void
	 */
	protected function createPasswordLists() {
		$passwordRows = $this->getDatabase()->exec_SELECTgetRows(
			'user_username, user_password, host',
			'tx_caretakerpasswordcracker_domain_model_user',
			'1=1'
		);

		$hashMethods = array_keys($this->hashMethodsWithJohnOptions);
		$hashArray = array();
		foreach ($hashMethods as $method) {
			$hashArray[$method] = array();
		}

		foreach ($passwordRows as $passwordRow) {
			$saltedPasswordInstance = tx_saltedpasswords_salts_factory::getSaltingInstance($passwordRow['user_password']);
			if (is_object($saltedPasswordInstance)) {
				$hashArray[get_class($saltedPasswordInstance)][] = array(
					'username' => $passwordRow['user_username'],
					'password' => $passwordRow['user_password'],
					'host' => $passwordRow['host'],
				);
			} else {
				// Simple md5 without salt
				if (preg_match('/[0-9abcdef]{32,32}/', $passwordRow['user_password'])) {
					$hashArray['md5'][] = array(
						'username' => $passwordRow['user_username'],
						'password' => $passwordRow['user_password'],
						'host' => $passwordRow['host'],
					);
				} else {
					// throw new Exception 'not recognized method'
				}
			}
		}

		foreach ($hashArray as $hashMethod => $hashItems) {
			$fileLocation = $this->getAbsolutePasswordListFileLocationFromHashMethod($hashMethod);
			@unlink($fileLocation);
			if (count($hashItems) > 0) {
				$content = array();
				foreach ($hashItems as $hashItem) {
					$content[] = $hashItem['host'] . '%' . $hashItem['username'] . ':' . $hashItem['password'];
				}
				t3lib_div::writeFile($fileLocation, implode(LF, $content));
			}
		}
	}

	/**
	 * Return absolute password file location for given
	 *
	 * @param string $hashMethod
	 * @return string
	 */
	protected function getAbsolutePasswordListFileLocationFromHashMethod($hashMethod) {
		return $this->johnDirectory . 'passwordLists/list-' . $hashMethod . '.txt';
	}

	/**
	 * Return absolute location of session file
	 *
	 * @param string $hashMethod
	 * @return string
	 */
	protected function getAbsoluteSessionFileLocationFromHashMethod($hashMethod) {
		return $this->johnDirectory . 'sessions/session-' . $hashMethod;
	}

	/**
	 * Get typo3 database class
	 *
	 * @return t3lib_DB
	 */
	protected function getDatabase() {
		return $GLOBALS['TYPO3_DB'];
	}
}

?>