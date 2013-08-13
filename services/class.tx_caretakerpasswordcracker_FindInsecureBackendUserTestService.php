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
 * Find insecure backend user passwords
 * This test service gets a list of enable backend users from
 * caretaker instances and writes them to a database table.
 *
 * The passwords can be tried to be crackend then. If a given
 * user / password combination is marked as cracked by a crack
 * service like john, the test will fail.
 *
 * @author Christian Kuhn <lolli@schwarzbu.ch>
 */
class tx_caretakerpasswordcracker_FindInsecureBackendUserTestService extends tx_caretakerinstance_RemoteTestServiceBase {

	/**
	 * @var bool Whether or not data was written to local user table: updated passwords or removed users
	 */
	protected $dataWasChanged = FALSE;

	/**
	 * @return tx_caretaker_TestResult
	 */
	public function runTest() {
		$operations = array(
			0 => array(
				'GetBackendUserList',
				array()
			)
		);

		$commandResult = $this->executeRemoteOperations($operations);
		if (!$this->isCommandResultSuccessful($commandResult)) {
		 	return $this->getFailedCommandResultTestResult($commandResult);
		}

		$results = $commandResult->getOperationResults();

		/** @var $result tx_caretakerinstance_OperationResult */
		$result = $results[0];
		if (!$result->isSuccessful()) {
			return tx_caretaker_TestResult::create(
				tx_caretaker_Constants::state_error,
				0,
				htmlspecialchars($result->getValue())
			);
		}

		// Successfully got all user data of an instance at this point
		try {
			$users = $this->sortOutUsers($result->getValue());
			$this->updateUsersInPasswordTable($users);
			$this->removeUsersNotSeenForSomeTime();
			$this->markChangedDataInRegistry();

			$crackedPasswordAccounts = $this->getCrackedPasswordAccountsOfInstance($users);
			if (count($crackedPasswordAccounts) > 0) {
				$testResult = tx_caretaker_TestResult::create(
					tx_caretaker_Constants::state_error,
					0,
					$this->getInsecurePasswordListMessage($crackedPasswordAccounts)
				);
			} else {
				$testResult = tx_caretaker_TestResult::create(
					tx_caretaker_Constants::state_ok,
					0,
					'No cracked password account found'
				);
			}
		} catch (Exception $e) {
			$testResult = tx_caretaker_TestResult::create(
				tx_caretaker_Constants::state_error,
				0,
				'Error in data processing: ' . $e->getMessage() . ' ' . $e->getCode()
			);
		}

		return $testResult;
	}

	/**
	 * If the procces changed some data (inserted, deleted or updated a user password),
	 * this is marked in the registry.
	 *
	 * The scheduler task uses and resets this information to re-create password
	 * list and restart john
	 *
	 * @return void
	 */
	protected function markChangedDataInRegistry() {
		if ($this->dataWasChanged); {
			/** @var $registry t3lib_Registry */
			$registry = t3lib_div::makeInstance('t3lib_Registry');
			$registry->set('tx_caretaker_password_cracker', 'changedPasswordData', TRUE);
		}
	}

	/**
	 * Create message from list of insecure accounts
	 *
	 * @param array $users
	 * @return string
	 */
	protected function getInsecurePasswordListMessage(array $users) {
		$message = array();
		foreach ($users as $user) {
			$message[] = 'Weak password, user name: ' . $user['username'];
		}
		return implode('<br />', $message);
	}

	/**
	 * Returns cracked password accounts of this instance
	 *
	 * @param array $users
	 * @return array Cracked users
	 */
	protected function getCrackedPasswordAccountsOfInstance(array $users) {
		$crackedPasswordAccounts = array();

		$crackedAccountRows = $this->getDatabase()->exec_SELECTgetRows(
			'*',
			'tx_caretakerpasswordcracker_domain_model_user',
			'cracked=1' .
				' AND host=' . $this->getDatabase()->fullQuoteStr($this->instance->getHostname(), 'tx_caretakerpasswordcracker_domain_model_user')
		);

		foreach($crackedAccountRows as $crackedAccountRow) {
			$username = $crackedAccountRow['user_username'];
			foreach ($users as $user) {
				if ($user['username'] === $username) {
					$crackedPasswordAccounts[] = $user;
				}
			}
		}

		return $crackedPasswordAccounts;
	}

	/**
	 * Removes all users from db that where not seen in caretaker for some time.
	 * This is some sort of garbage collection for instances that are gone and
	 * deleted users
	 *
	 * @return void
	 */
	protected function removeUsersNotSeenForSomeTime() {
		$this->getDatabase()->exec_DELETEquery(
			'tx_caretakerpasswordcracker_domain_model_user',
			'tstamp < ' . ($GLOBALS['EXEC_TIME'] - 2 * 24 * 60 * 60)
		);
		if ($this->getDatabase()->sql_affected_rows() > 0) {
			$this->dataWasChanged = TRUE;
		}
	}

	/**
	 * Stuff / update user data in password table
	 *
	 * @param array $users
	 */
	protected function updateUsersInPasswordTable(array $users) {
		foreach ($users as $user) {
			$currentUserRecord = $this->getCurrentUserRecord($user);
			if (count($currentUserRecord) === 0) {
				$currentUserRecord = $this->insertUserRecord($user);
			}
			// Update if p/w changed
			if ($user['password'] !== $currentUserRecord['user_password']) {
				$this->updatePasswordInRecord($user, $currentUserRecord);
			}
			// Update 'last seen this user timestamp'
			$this->updateUserRecordTimestamp($currentUserRecord);
		}
	}

	/**
	 * Update record timestamp
	 *
	 * @param array $currentUserRecord
	 */
	protected function updateUserRecordTimestamp(array $currentUserRecord) {
		$this->getDatabase()->exec_UPDATEquery(
			'tx_caretakerpasswordcracker_domain_model_user',
			'uid=' . $this->getDatabase()->fullQuoteStr($currentUserRecord['uid'], 'tx_caretakerpasswordcracker_domain_model_user'),
			array(
				'tstamp' => $GLOBALS['EXEC_TIME']
			)
		);
	}

	/**
	 * Update user password, and set cracked value to 0 again
	 *
	 * @param array $user
	 * @param array $currentUserRecord
	 */
	protected function updatePasswordInRecord(array $user, array $currentUserRecord) {
		$this->getDatabase()->exec_UPDATEquery(
			'tx_caretakerpasswordcracker_domain_model_user',
			'uid=' . $this->getDatabase()->fullQuoteStr($currentUserRecord['uid'], 'tx_caretakerpasswordcracker_domain_model_user'),
			array(
				'user_password' => $user['password'],
				'cracked' => 0
			)
		);
		$this->dataWasChanged = TRUE;
	}

	/**
	 * Get current user record
	 *
	 * @param array $user Current user information
	 * @return array user record in table, or empty array
	 * @throws Exception
	 */
	protected function getCurrentUserRecord(array $user) {
		$rows = $this->getDatabase()->exec_SELECTgetRows(
			'*',
			'tx_caretakerpasswordcracker_domain_model_user',
			'user_username=' . $this->getDatabase()->fullQuoteStr($user['username'], 'tx_caretakerpasswordcracker_domain_model_user') .
				' AND host=' . $this->getDatabase()->fullQuoteStr($this->instance->getHostname(), 'tx_caretakerpasswordcracker_domain_model_user') .
				' AND deleted=0'
		);
		if ($rows === NULL) {
			throw new Exception('Query error', 1354879347);
		}
		if (count($rows) > 1) {
			throw new Exception('Database integrity error', 1354879391);
		}
		$user = array();
		if (count($rows) === 1) {
			$user = array_shift($rows);
		}
		return $user;
	}

	/**
	 * Insert fresh user record in db
	 *
	 * @param array $user
	 * @return array user record in table
	 */
	protected function insertUserRecord(array $user) {
		$this->getDatabase()->exec_INSERTquery(
			'tx_caretakerpasswordcracker_domain_model_user',
			array(
				'tstamp' => $GLOBALS['EXEC_TIME'],
				'crdate' => $GLOBALS['EXEC_TIME'],
				'user_username' => $user['username'],
				'user_password' => $user['password'],
				'host' => $this->instance->getHostname(),
				'cracked' => 0
			)
		);
		$this->dataWasChanged = TRUE;
		return $this->getCurrentUserRecord($user);
	}

	/**
	 * Sort out users that can not log in.
	 *
	 * @param array $users from an instance
	 * @return array Users with data
	 */
	protected function sortOutUsers(array $users) {
		$usersToCheck = array();
		foreach ($users as $user) {
			// Base fields must exist
			if (
				!array_key_exists('uid', $user)
				|| !array_key_exists('pid', $user)
				|| !array_key_exists('username', $user)
				|| !array_key_exists('password', $user)
				|| !array_key_exists('admin', $user)
				|| !array_key_exists('tstamp', $user)
				|| !array_key_exists('disable', $user)
				|| !array_key_exists('starttime', $user)
				|| !array_key_exists('endtime', $user)
				|| !array_key_exists('crdate', $user)
				|| !array_key_exists('deleted', $user)
			) {
				continue;
			}
			// No disabled or deleted users
			if (is_numeric($user['disable']) && $user['disable'] == 1) {
				continue;
			}
			if (is_numeric($user['deleted']) && $user['deleted'] == 1) {
				continue;
			}
			if (is_numeric($user['starttime']) && $user['starttime'] > 0 && $user['starttime'] > $GLOBALS['EXEC_TIME']) {
				continue;
			}
			if (is_numeric($user['endtime']) && $user['endtime'] > 0 && $user['endtime'] < $GLOBALS['EXEC_TIME']) {
				continue;
			}
			// Empty password (eg. from other login services) are not interesting for us
			if (mb_strlen($user['password']) === 0) {
				continue;
			}
			// Users starting with _cli_ can not log in
			if (mb_substr($user['username'], 0, 5) === '_cli_') {
				continue;
			}

			$usersToCheck[] = $user;
		}
		return $usersToCheck;
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
