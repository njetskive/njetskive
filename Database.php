<?php

// includes
include_once('constants.php');

/**
 * Database class
 */
class Database {
	
	/**
	 * Database object
	 * 
	 * @access protected
	 * @var PDO
	 */
	protected $DB;
	
	/**
	 * Database driver
	 * 
	 * @access protected
	 * @var string
	 */
	protected $DRIVER;
	
	/**
	 * Database host
	 * 
	 * @access protected
	 * @var string
	 */
	protected $HOST;
	
	/**
	 * Database name
	 * 
	 * @access protected
	 * @var string
	 */
	protected $NAME;
	
	/**
	 * Charset to use
	 * Is set by default for security reasons
	 * @access protected
	 * @var string
	 */
	protected $CHARSET = 'utf8';
	
	/**
	 * Database user
	 * 
	 * @access protected
	 * @var string
	 */
	protected $USER;
	
	/**
	 * Database password
	 * 
	 * @access protected
	 * @var string
	 */
	protected $PASS;
	
	/**
	 * Constructor
	 * 
	 * Creates the $DB object and connects to the database.
	 *
	 * @param array $args connection options
	 */
	function __construct($args = null) {
		
		// assign from given constants
		$this->DRIVER = defined('DB_DRIVER') ? DB_DRIVER : null;
		$this->HOST = defined('DB_HOST') ? DB_HOST : null;
		$this->NAME = defined('DB_NAME') ? DB_NAME : null;
		$this->USER = defined('DB_USER') ? DB_USER : null;
		$this->PASS = defined('DB_PASS') ? DB_PASS : null;
		
		// assign from given arguments
		if ( $args != null ) {
			if ( $args['driver'] != null ) $this->DRIVER = $args['driver'];
			if ( $args['host'] != null ) $this->HOST = $args['host'];
			if ( $args['name'] != null ) $this->NAME = $args['name'];
			if ( $args['charset'] != null ) $this->CHARSET = $args['charset'];
			if ( $args['user'] != null ) $this->USER = $args['user'];
			if ( $args['pass'] != null ) $this->PASS = $args['pass'];
		}
		
		
		// Connect to database
		$this->connect();
		
	}
	
	
	/**
	 * Destructor
	 * 
	 * Closes the database connection by setting $DB to null
	 */
	function __destruct() {
		$this->DB = null;
	}
	
	/**
	 * Connect to the database.
	 * 
	 * @return bool
	 */
	function connect() {
		
		/**
		 * Initialize $DB object
		 */
		try {
			
			if ( DB_DRIVER == 'mysql' ) { // MySQL
				$this->DB = new PDO(
					// Database driver
					$this->DRIVER .
					
					// Database host
					':host=' . $this->HOST .
					
					// Database name
					';dbname=' . $this->NAME .
					
					// Charset
					';charset=' . $this->CHARSET,
					
					// Database username
					$this->USER,
					
					// Database password
					$this->PASS
				);
			}
			else if ( DB_DRIVER == 'sqlsrv') { // MS-SQL
				$this->DB = new PDO(
					// Database driver
					$this->DRIVER .
					
					// Database host
					':Server=' . $this->HOST .
					
					// Database name
					';Database=' . $this->NAME .
					
					// Charset
					';charset=' . $this->CHARSET,
					
					// Database username
					$this->USER,
					
					// Database password
					$this->PASS
				);
			}
			
			// Set error mode
			$this->DB->setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
			
			// Use actual prepared statements
			$this->DB->setAttribute( PDO::ATTR_EMULATE_PREPARES, false );
			
		}
		catch( PDOException $e ) {
			die( "ERROR: " . $e->getMessage() );
		}
		
		return true;
	}
	
	/**
	 * Changes the database to use
	 * 
	 * @param string $name the database to use
	 * @return bool
	 */
	function changeDatabase($name) {
		$this->close();
		
		$this->NAME = $name;
		
		$this->connect();
		
		return true;
	}
	
	/**
	 * Closes the database connection by setting $DB to null
	 * 
	 * @return bool
	 */
	function close() {
		$this->DB = null;
		
		return true;
	}
	
	/**
	 * Query
	 * --------
	 * Custom query
	 * 
	 * @return true if successful
	 */
	function Query($query, $args = null) {
		
		$STMT = $this->DB->prepare($query);
		
		if ( $args != null ) {
			
			for ( $i = 0; $i < sizeof($args); $i++ ) {
				$STMT->bindParam(($i + 1), $args[$i]);
			}
			
		}
		
		return $STMT->execute();
		
	}
	
	/**
	 * Select
	 * --------
	 * Passes a select query
	 * 
	 * @return array
	 */
	function Select($query, $args = null) {
		
		$STMT = $this->DB->prepare($query);
		
		if ( $args != null ) {
			
			for ( $i = 0; $i < sizeof($args); $i++ ) {
				$STMT->bindParam(($i + 1), $args[$i]);
			}
			
		}
		
		$STMT->execute();
		
		return $STMT->fetch(PDO::FETCH_ASSOC);
		
	}
	
	/**
	 * Insert
	 * --------
	 * Inserts into database
	 * 
	 * @return true if successful
	 */
	function Insert($query, $args = null) {
		
		$STMT = $this->DB->prepare($query);
		
		if ( $args != null ) {
			
			for ( $i = 0; $i < sizeof($args); $i++ ) {
				$STMT->bindParam(($i + 1), $args[$i]);
			}
			
		}
		
		return $STMT->execute();
		
	}
	
	/**
	 * Replace
	 * --------
	 * Replaces record if exists. Inserts into database if not
	 * 
	 * @return true if successful
	 */
	function Replace($query, $args = null) {
		
		$STMT = $this->DB->prepare($query);
		
		if ( $args != null ) {
			
			for ( $i = 0; $i < sizeof($args); $i++ ) {
				$STMT->bindParam(($i + 1), $args[$i]);
			}
			
		}
		
		return $STMT->execute();
		
	}
	
	/**
	 * Update
	 * --------
	 * Updates a record
	 * 
	 * @return int returns affected rows count
	 */
	function Update($query, $args = null) {
		
		$STMT = $this->DB->prepare($query);
		
		if ( $args != null ) {
			
			for ( $i = 0; $i < sizeof($args); $i++ ) {
				$STMT->bindParam(($i + 1), $args[$i]);
			}
			
		}
		
		$STMT->execute();
		
		return $STMT->rowCount();
		
	}
	
	/**
	 * Delete
	 * --------
	 * Deletes given records
	 * 
	 * @return int returns affected rows count
	 */
	function Delete($query, $args = null) {
		
		$STMT = $this->DB->prepare($query);
		
		if ( $args != null ) {
			
			for ( $i = 0; $i < sizeof($args); $i++ ) {
				$STMT->bindParam(($i + 1), $args[$i]);
			}
			
		}
		
		$STMT->execute();
		
		return $STMT->rowCount();
		
	}
	
}
