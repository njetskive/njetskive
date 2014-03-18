<?php

// require database class
require_once('Database.php');
require_once('Session.php');

/**
 * User class
 */
class User {
	
	public $Name;
	protected $Email;
	protected $Id;
	protected $Password;
	
	protected $salt;
	
	protected $Database;
	protected $Session;
	public $session_prefix = 'njetskive-';
	
	function __construct($args = null) {
		
		// generate salt
		$this->salt = hash('sha512', uniqid(openssl_random_pseudo_bytes(16), TRUE));
		
		// assign from given arguments
		if ( $args != null ) {
			if ( $args['id'] != null ) $this->Id = $args['id'];
			if ( $args['name'] != null ) $this->Name = $args['name'];
			if ( $args['email'] != null ) $this->Email = $args['email'];
			if ( $args['password'] != null ) $this->Password = $args['password'];
		}
		
		// initialize database connection
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
			CREATE TABLE IF NOT EXISTS `users` (
				`id` INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
				`username` VARCHAR(30) NOT NULL,
				`email` VARCHAR(50) NOT NULL,
				`password` CHAR(128) NOT NULL,
				`salt` CHAR(128) NOT NULL,
				`temp_key` CHAR(128) NOT NULL,
				`api_key` CHAR(128) NOT NULL,
				`register_key` CHAR(128) NOT NULL,
				`creation_date` DATETIME NOT NULL,
				`last_login` DATETIME NOT NULL,
				`last_login_fail` DATETIME NOT NULL,
				`failed_login_attemts` INT NOT NULL,
				`status` INT NOT NULL
			) ENGINE = InnoDB;
		');
		
	}
	
	/**
	 * setName
	 * --------
	 * Set Name
	 */
	function setName($name) {
		$this->Name = $name;
		
		if ($this->Name == $name) return true;
		else return false;
	}
	
	/**
	 * setPassword
	 * --------
	 * Set Password
	 */
	function setPassword($password) {
		$this->Password = $password;
		
		if ($this->Password == $password) return true;
		else return false;
	}
	
	/**
	 * getName
	 */
	function getName() {
		return $this->Name;
	}
	
	/**
	 * getEmail
	 */
	function getEmail() {
		return $this->Email;
	}
	
	
	/**
	 * getId
	 */
	function getId() {
		return $this->Id;
	}
	
	/**
	 * getPassword
	 */
	function getPassword() {
		return $this->Password;
	}
	
	/**
	 * Register
	 * --------
	 * Registers user
	 */
	function Register($args = null) {
		
		// assign from given arguments
		if ( $args != null ) {
			if ( isset($args['name']) ) $this->Name = $args['name'];
			if ( isset($args['email']) ) $this->Email = $args['email'];
			if ( isset($args['password']) ) $this->Password = $args['password'];
		}
		
		if (!isset($this->Name) && isset($this->Email)) $this->Name = $this->Email;
		
		// Hash values
		$this->Password = $this->makeHash($this->Password, $this->salt);
		
		if (!isset($this->Email)) { // Register without email
			
			if (isset($this->Name, $this->Password) && !$this->Exist($this->Name)) {
				
				$this->Email = 'NO EMAIL';
				
				$now = date("Y-m-d H:i:s");
				$user_browser = $_SERVER['GET_USER_AGENT'];
				$register_key = 0;
				$status = 1;
				
				$this->Database->Insert(
					'INSERT INTO users(username, email, password, salt, register_key, status, creation_date) VALUES(?, ?, ?, ?, ?, ?, ?)',
					array(
						$this->Name,
						$this->Email,
						$this->Password,
						$this->salt,
						$register_key,
						$status,
						$now
					)
				);
				
				return true;
			}
			else
				return false;
			
		}
		else { // Register with email
			
			if (isset($this->Name, $this->Password, $this->Email) && !$this->Exist($this->Name)) {
				
				$now = date("Y-m-d H:i:s");
				$user_browser = $_SERVER['GET_USER_AGENT'];
				$register_key = $this->makeHash($now, $user_browser);
				$status = 0;
				
				$this->Database->Insert(
					'INSERT INTO users(username, email, password, salt, register_key, status, creation_date) VALUES(?, ?, ?, ?, ?, ?, ?)',
					array(
						$this->Name,
						$this->Email,
						$this->Password,
						$this->salt,
						$register_key,
						$status,
						$now
					)
				);
				
				$this->sendRegisterEmail($this->Email, $register_key);
				
				return true;
			}
			else
				return false;
			
		}
		
	}
	
	/**
	 * verifyAccount
	 * --------
	 * @return true if successful
	 */
	function verifyAccount($verification_code) {
		
		if (isset($verification_code)) {
			$result = $this->Database->Select('SELECT id, status FROM users WHERE register_key=?', array($verification_code));
			if (sizeof($result) == 2) {
				
				if ($result['status'] == 0) {
					$update = $this->Database->Update('UPDATE users SET status=? WHERE id=? LIMIT 1', array(1, $result['id']));
					
					return true;
				}
				else
					return false;
			}
			else
				return false;
		}
		else
			return false;
		
	}
	
	/**
	 * Authenticate
	 * --------
	 */
	function Authenticate($username = null, $password = null) {
		
		if (isset($username)) $this->Name = $username;
		if (isset($password)) $this->Password = $password;
		
		if (!isset($this->Name)) $this->Name = $this->Email;
		
		if (isset($this->Name, $this->Password)) {
			
			$result = $this->Database->Select('SELECT id, username, password, salt, status FROM users WHERE username=? LIMIT 1', array($this->Name));
			
			if (sizeof($result) == 5) {
				
				$this->Id = $result['id'];
				$this->Password = $this->makeHash($this->Password, $result['salt']);
				
				if (!$this->isBrute($this->Id)) {
					
					if ($result['password'] == $this->Password) {
						
						if ($result['status'] == 1) {
							
							if ( session_status() === PHP_SESSION_NONE ) session_start();
							
							// XSS protection as we might print this value
							$user_id = preg_replace("/[^0-9]+/", "", $this->Id);
							$_SESSION[$this->session_prefix . 'user_id'] = $user_id;
							
							// XSS protection as we might print this value
							$user_name = preg_replace("/[^a-zA-Z0-9@.-_\-]+/", "", $this->Name);
							$_SESSION[$this->session_prefix . 'user_name'] = $user_name;
							
							$user_browser = $_SERVER['HTTP_USER_AGENT'];
							$temp_key = $this->makeHash($this->Password, $user_browser);
							$_SESSION[$this->session_prefix . 'temp_key'] = $temp_key;
							
							$now = date("Y-m-d H:i:s");
							
							$this->Database->Update('UPDATE users SET temp_key=?, last_login=?, failed_login_attemts=0 WHERE id=? LIMIT 1', array($temp_key, $now, $this->Id));
							
							return true;
						}
						else
							return false;
						
					}
					else {
						
						$now = date("Y-m-d H:i:s");
						
						$this->Database->Update('UPDATE users SET last_login_fail=?, failed_login_attemts=failed_login_attemts+1 WHERE id=?', array($now, $this->Id));
						
						return false;
					}
				}
				else
					return false;
			}
			else
				return false;
		}
		else
			return false;
	}
	
	/**
	 * deAuthenticate
	 * --------
	 */
	function deAuthenticate() {
		
		if ( session_status() != PHP_SESSION_NONE ) {
			
			// Unset all session values 
			$_SESSION = array();
			
			// get session parameters 
			$params = session_get_cookie_params();
			
			// Delete the actual cookie. 
			setcookie(
				session_name(),
				'',
				time() - 42000, 
				$params["path"], 
				$params["domain"], 
				$params["secure"], 
				$params["httponly"]
			);
			
			// Destroy session
			session_destroy();
			
			return true;
		}
		else
			return false;
		
	}
	
	/**
	 * isAuthenticated
	 */
	function isAuthenticated() {
		
		if (isset($_SESSION[$this->session_prefix . 'user_id'], $_SESSION[$this->session_prefix . 'user_name'], $_SESSION[$this->session_prefix . 'temp_key'])) {
			$user_id = $_SESSION[$this->session_prefix . 'user_id'];
			$user_name = $_SESSION[$this->session_prefix . 'user_name'];
			$temp_key = $_SESSION[$this->session_prefix . 'temp_key'];
			
			$user_browser = $_SERVER['HTTP_USER_AGENT'];
			
			$result = $this->Database->Select('SELECT password FROM users WHERE id=? LIMIT 1', array($user_id));
			
			if (sizeof($result) == 1) {
				
				if ($temp_key == $this->makeHash($result['password'], $user_browser))
					return true;
				
				else
					return false;
			}
			else
				return false;
		}
		else
			return false;
		
	}
	
	/**
	 * Remove
	 * --------
	 */
	function Remove($id = null) {
		
		if (isset($id)) $this->Id = $id;
		
		if (isset($this->Id)) {
			
			$result = $this->Database->Delete('DELETE FROM users WHERE id=? LIMIT 1', array($this->Id));
			
			if ($result == 1) return true;
			else return false;
			
		}
		else
			return false;
		
	}
	
	/**
	 * destroyDatabase
	 */
	function destroyDatabase($true) {
		
		if ($true) {
			return $this->Database->Query('DROP TABLE IF EXISTS users');
		}
		else
			return false;
		
	}
	
	/**
	 * Exist
	 */
	function Exist($name) {
		
		$result = $this->Database->Select('SELECT id FROM users WHERE username=?', array($name));
		
		if ($result == false)
			return false;
		else
			return true;
		
	}
	
	/**
	 * makeHash
	 * --------
	 * Hashes the password hith the salt
	 */
	function makeHash($password, $salt = null) {
		
		if (isset($salt))
			$hashed = hash('sha512', $password . $salt);
		else
			$hashed = hash('sha512', $password);
		
		return $hashed;
	}
	
	/**
	 * isBrute
	 * --------
	 */
	function isBrute($id) {
		
		$now = time();
		
		$valid_attemts = $now - 2 * 60 * 60;
		
		$result = $this->Database->Select('SELECT failed_login_attemts FROM users WHERE id=? AND last_login_fail > ?', array($id, $valid_attemts));
		
		if ($result['failed_login_attemts'] >= 5) return true;
		else return false;
		
	}
	
	/**
	 * sendRegisterEmail
	 */
	function sendRegisterEmail($recipient, $register_key) {
		
		$verification_link = 'href="http://test.minstatistik.se/register?v=' . $register_key . '"';
		
		$sender = 'Go Statistics <donotreply@minstatistik.se>';
		
		$subject = "Go Statistics Verifiera ditt konto";
		
		$header = <<<HEADER
From: $sender
Content-Type: text/html;
HEADER;
		
		$message = <<<MESSAGE
<table width="100%">
	<tr>
		<td>
			<table width="100%" align="center">
				<tr>
					<td align="center">
						<span style="color: #292">Go</span> Statistics
					</td>
				</tr>
				<tr>
					<td align="center">
						<br>
					</td>
				</tr>
				<tr>
					<td align="center">
						Hej!<br>
						Tack för att du registrerat ett konto på <span style="color: #292">Go</span> Statistics, för att få full tillgång till tjänsten behöver du verifiera ditt konto
						genom att klicka på länken nedan.
					</td>
				</tr>
				<tr>
					<td align="center">
						<br>
					</td>
				</tr>
				<tr>
					<td align="center">
						Ditt användarnamn: $this->Name<br>
						<a $verification_link style="color: #292">Verifiera Konto</a>
					</td>
				</tr>
				<tr>
					<td align="center">
						<br>
					</td>
				</tr>
				<tr>
					<td align="center">
						Känner du inte alls igen detta?<br>
						Bara lugn, då kan du bortse från detta meddelande helt och hållet.
					</td>
				</tr>
				<tr>
					<td align="center">
						<hr>
					</td>
				</tr>
				<tr>
					<td align="center">
						Martin Pettersson
					</td>
				</tr>
			</table>
		</td>
	</tr>
</table>
MESSAGE;
		
		if (mail($recipient, $subject, $message, $header))
			return true;
		else
			return false;
		
	}
	
}
