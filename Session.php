<?php

// require database class
require_once('Database.php');

/**
 * Session class
 */
class Session {
	
	protected $Database;
	
	private $salt;
	
	function __construct() {
		
		// session functions
		session_set_save_handler(array($this, 'open'), array($this, 'close'), array($this, 'read'), array($this, 'write'), array($this, 'destroy'), array($this, 'gc'));
		
		// This line prevents unexpected effects when using objects as save handlers.
		register_shutdown_function('session_write_close');
		
		$this->salt = hash('sha512', date('c'));
		
		$this->Database = new Database();
		
		$this->setupDatabase();
		
	}
	
	/**
	 * setupDatabase
	 * --------
	 * Sets up the database
	 */
	function setupDatabase() {
		
		$this->Database->Query('
			CREATE TABLE IF NOT EXISTS `sessions` (
				`id` CHAR(128) NOT NULL,
				`set_time` CHAR(10) NOT NULL,
				`data` text NOT NULL,
				`session_key` CHAR(128) NOT NULL,
				PRIMARY KEY (`id`)
			) ENGINE=InnoDB DEFAULT CHARSET=latin1
		');
		
	}
	
	function Start($session_name, $secure) {
		// Make sure the session cookie is not accessable via javascript.
		$httponly = true;
		
		// Hash algorithm to use for the sessionid
		$session_hash = 'sha512';
		
		// Check if hash is available
		if (in_array($session_hash, hash_algos())) {
			// Set the has function.
			ini_set('session.hash_function', $session_hash);
		}
		
		// How many bits per character of the hash.
		// The possible values are '4' (0-9, a-f), '5' (0-9, a-v), and '6' (0-9, a-z, A-Z, "-", ",").
		ini_set('session.hash_bits_per_character', 5);
		
		// Force the session to only use cookies, not URL variables.
		ini_set('session.use_only_cookies', 1);
		
		// Get session cookie parameters 
		$cookieParams = session_get_cookie_params(); 
		
		// Set the parameters
		session_set_cookie_params($cookieParams["lifetime"], $cookieParams["path"], $cookieParams["domain"], $secure, $httponly); 
		
		// Change the session name 
		session_name($session_name);
		
		// Now we cat start the session
		session_start();
		
		// This line regenerates the session and delete the old one. 
		// It also generates a new encryption key in the database. 
		session_regenerate_id(true);
	}
	
	/**
	 * open
	 * --------
	 * This function will be called by the PHP sessions when we start a new session,
	 * we use it to start a new database connection.
	 */
	function open() {
		
		return $this->Database->connect();
		
	}
	
	/**
	 * close
	 * --------
	 * This function will be called when the sessions want to be closed.
	 */
	function close() {
		
		return $this->Database->close();
		
	}
	
	/**
	 * read
	 * --------
	 * This function will be called by PHP when we try to access a session for example
	 * when we use echo $_SESSION['something'];
	 */
	function read($id) {
		
		$data = $this->Database->Select('SELECT data FROM sessions WHERE id=? LIMIT 1', array($id))['data'];
		
		$data = $this->decrypt($data, $key);
		
		return $data;
		
	}
	
	/**
	 * write
	 * --------
	 * This function is used when we assign a value to a session,
	 * for example $_SESSION['something'] = 'something else';.
	 * The function encrypts all the data which gets inserted into the database.
	 */
	function write($id, $data) {
		// Get unique key
		$key = $this->getkey($id);
		
		// Encrypt the data
		$data = $this->encrypt($data, $key);
		
		$time = time();
		
		return $this->Database->Replace(
			'REPLACE INTO sessions (id, set_time, data, session_key) VALUES (?, ?, ?, ?)',
			array(
				$id,
				$time,
				$data,
				$key
			)
		);
		
	}
	
	/**
	 * destroy
	 * --------
	 * This function deletes the session from the database, it is used by php when we
	 * call functions like session__destroy();.
	 */
	function destroy($id) {
		
		$rowCount = $this->Database->Delete('DELETE FROM sessions WHERE id=?', array($id));
		
		if ($rowCount != 0)
			return true;
		else
			return false;
	}
	
	
	/**
	 * gc
	 * --------
	 * This function is the garbage collecter function it is called to delete old sessions.
	 * The frequency in which this function is called is determined by two configuration directives,
	 * session.gc_probability and session.gc_divisor.
	 */
	function gc($max) {
		
		$old = time() - $max;
		
		$result = $this->Database->Delete('DELETE FROM sessions WHERE set_time < ?', array($old));
		
		if ($result != 0)
			return true;
		else
			return false;
	}
	
	/**
	 * getkey
	 * --------
	 * This function is used to get the unique key for encryption from the sessions table.
	 * If there is no session it just returns a new random key for encryption.
	 */
	private function getkey($id) {
		
		$result = $this->Database->Select('SELECT session_key FROM sessions WHERE id=? LIMIT 1', array($id));
		
		if ($result == false) {
			$random_key = hash('sha512', uniqid(mt_rand(1, mt_getrandmax()), true));
			return $random_key;
		}
		else
			return $result['key'];
	}
	
	private function encrypt($data, $key) {
		
		$key = substr(hash('sha256', $this->salt . $key . $this->salt), 0, 32);
		
		$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
		
		$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
		
		$encrypted = base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $key, $data, MCRYPT_MODE_ECB, $iv));
		
		return $encrypted;
		
	}
	
	private function decrypt($data, $key) {
		
		$key = substr(hash('sha256', $this->salt . $key . $this->salt), 0, 32);
		
		$iv_size = mcrypt_get_iv_size(MCRYPT_RIJNDAEL_256, MCRYPT_MODE_ECB);
		
		$iv = mcrypt_create_iv($iv_size, MCRYPT_RAND);
		
		
		$decrypted = mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $key, base64_decode($data), MCRYPT_MODE_ECB, $iv);
		
		return $decrypted;
	}
	
}
