<?php
/**
*            _       _ _    _                      _   _      _   
*           (_)     (_) |  | |                    | \ | |    | |  
*  _ __ ___  _ _ __  _| |__| | ___  _ __ ___   ___|  \| | ___| |_ 
* | '_ ` _ \| | '_ \| |  __  |/ _ \| '_ ` _ \ / _ \ . ` |/ _ \ __|
* | | | | | | | | | | | |  | | (_) | | | | | |  __/ |\  |  __/ |_ 
* |_| |_| |_|_|_| |_|_|_|  |_|\___/|_| |_| |_|\___|_| \_|\___|\__|
* (c) 2106 dumplab
*
*  poor man's HTTP miniHomeNet. This script acting as the relay.
*
* Requirements:
* =============
* - PDO sqlite
*
* Usage:
* ======
* 1.) copy this file to your webserver. Make sure the webserver supports PDO sqlite
* 2.) change the password to access to the WebUI (UI_PASSWORD), change the secret (NET_AUTO_REGISTER_SECRET)
* 3.) secure the database file using .htaccess with use AllowOverwrite All in apache for example:
*     <Files "minihomenetdb.php">
*     Order Allow,Deny
*     Deny from all
*     </Files>
*
* License:
* ========
* This software is provided 'as-is', without any express or implied
* warranty. In no event will the authors be held liable for any damages
* arising from the use of this software.
*
* Permission is granted to anyone to use this software for any purpose,
* including commercial applications, and to alter it and redistribute it
* freely.
* 
* @author    dumplab
* @copyright 2016 dumplab
* @version   $Id: minihomenet.php,v 0.17$;
*/

//ini_set('display_errors', 1);
//ini_set('display_startup_errors', 1);
//error_reporting(E_ALL);

// *************************
// * Default configuration *
// *************************
define('UI_PASSWORD'                ,'welcomexy');                   // WebUI Password to manage your devices, please change this
define('UI_ENABLED'                 ,true);                          // enable WebUI
define('NET_AUTO_REGISTER_ENABLED'  ,true);                          // enable guest logins, only supported method at the moment
define('NET_AUTO_REGISTER_SECRET'   ,'myp3s0nals3cr3t');             // default secret for guest registrations and login
define('DISPLAY_LOG_ROWS'           ,'50');                          // default value to show last 50 log and blocked ip entries in WebUI
define('SRV_NAME'                   ,'Example');                     // default server name
define('SRV_MOTD'                   ,'Because we like to command .');// default message of the day. displayed as welcome text during login
define('KEEPALIVE_TIME'             ,'20');                          // default keepalive time in seconds, devices missing 4x KEEPALIVES are considered offline in database
define('DEVICE_NAME_MIN_CHARS'      ,2);                             // minimum chars in devicename
define('DEVICE_NAME_MAX_CHARS'      ,32);                            // maximum allowed chars in devicename
define('MESSAGE_MIN_CHARS'          ,1);                             // minimum expected chars in a message
define('MESSAGE_MAX_CHARS'          ,500);                           // maximum allowed chars in a message
define('MAX_REGISTERED_DEVICE'      ,'10');                          // default maximum allowed number of devices registered in database
define('LOGGING_ENABLED'            ,'true');                        // default log all messages
define('IP_BLOCK_TIME'              ,'180');                         // IP-Address block time (seconds)
// *************************
// *  CODES do not change  *
// *************************
// Request codes
define('NET_GUEST_LOGIN'        ,'0099');
define('NET_LOGIN'              ,'0100');
define('NET_PING'               ,'0101');
define('NET_LOGOUT'             ,'0102');
define('NET_DEVICE_RENAME'      ,'0103');
define('NET_SEND_MESSAGE'       ,'0104');
define('NET_RETRIEVE_MESSAGE'   ,'0105');
define('NET_DEVICE_LIST'        ,'0106');
define('NET_SEND_INVITE'        ,'0109');
define('NET_SEND_JOIN'          ,'0110');
//  Response codes
define('NET_REQUEST_OK'         ,'0200');
define('NET_EXEC_MESSAGE'       ,'0201');
define('NET_REQUEST_UNKNOWN'    ,'0400');
define('NET_SECRET_REQUIRED'    ,'0401');
define('NET_SECRET_WRONG'       ,'0402');
define('NET_DEVICE_UNKNOWN'     ,'0403');
define('NET_DEVICE_LOGIN_FIRST' ,'0404');
define('NET_SERVER_MAX_DEVICE'  ,'0405');
define('NET_IP_ADDR_BLOCKED'    ,'0406');
define('NET_GUEST_LOGIN_OFF'    ,'0407');
define('NET_DATABASE_ERROR'     ,'0408');
define('NET_NAME_FORMAT_ERROR'  ,'0600');
define('NET_UID_FORMAT_ERROR'   ,'0601');
define('NET_MSG_FORMAT_ERROR'   ,'0602');
define('NET_INVALID_HIGHSCORE'  ,'0603');
define('NET_MSG_AWAITING'       ,'0700');
// Exec codes
define('EXEC_PRINT_MESSAGE'     ,'0800');
define('EXEC_SHUTDOWN_SYSTEM'   ,'0801');
define('EXEC_STOP_SCRIPT'       ,'0802');
define('EXEC_REMOTE_COMMAND'    ,'0803');

// Version
define('MINIHOMENET_VERSION'     ,'0.1');

class cDatabase
{
	private $fileName;
	private $db;
	private $dbCatch;
	private $response;

	/**
	* constructor
	*
	* @return just instantiate the class
	*/
	function __construct()
	{
		// File where we store the data ...
		// Note: use this php script + db only when your server is running apache(2) or
		// an htaccess-enabled one. Else open up the script file and adjust the DB-path
		// to be outside of the public-html-area of your server directory. Else you
		// allow people to just target the db (by the default db name the script uses) and download it.
		$this->fileName  = "minihomenetdb.php";
		$this->response  = new cResponse();
		// handle
		$this->db        = NULL;
		$this->dbCatch   = 0;
		$this->connect();
	}

	/**
    * connect database
	*
    * @return void
	* @access private
    */
	private function connect()
	{
		// connect database
		try
		{
			$this->db = new PDO("sqlite:".$this->fileName);
			$this->db->setAttribute(PDO::ATTR_ERRMODE,PDO::ERRMODE_EXCEPTION);
			// Create <?php table ... why ? make it impossible for people to download the data inside your database
			$this->db->exec("CREATE TABLE IF NOT EXISTS '<?php'  (id INTEGER PRIMARY KEY,uid TEXT, upw TEXT,name TEXT,email TEXT,ipv4 TEXT,online INTEGER,description TEXT,created INTEGER,lastupdate INTEGER)");		
			// Create tables
			$this->db->exec("CREATE TABLE IF NOT EXISTS device   (id INTEGER PRIMARY KEY,uid TEXT, upw TEXT,name TEXT,email TEXT,ipv4 TEXT,online INTEGER,description TEXT,created INTEGER,lastupdate INTEGER)");
			$this->db->exec("CREATE TABLE IF NOT EXISTS log      (id INTEGER PRIMARY KEY,time INTEGER,severity INTEGER, message)");
			$this->db->exec("CREATE TABLE IF NOT EXISTS ipblock  (time INTEGER,ipv4 TEXT,counter INTEGER)");
			$this->db->exec("CREATE TABLE IF NOT EXISTS msg      (id INTEGER PRIMARY KEY,uidFrom TEXT,uidTo TEXT,cmd TEXT, message TEXT,created INTEGER,transmitted INTEGER)");
		}
		catch(PDOException $e)
		{
			$this->dbCatch++;
			if ($this->dbCatch > 5) { $this->response->back(NET_DATABASE_ERROR,$e->getMessage()); }
			usleep(rand(10000,500000));
			$this->connect();
		}
		// sometimes this happend
		//  Uncaught exception 'PDOException' with message 'SQLSTATE[HY000]: General error: 5 database is locked' in ....minihomenet.php
	}

	public function logMessage($message,$sev=7)
	{
		// at this moment we use severity 7 only ... could be changed for each log entry
		if (LOGGING_ENABLED) { $this->db->exec("INSERT INTO log (time, severity, message) VALUES ('".date("U")."','".$sev."','".$message."');"); }
	}

	public function purgeLog()
	{
		$this->db->exec("DELETE from log");
	}

	public function isBlocked($ipv4)
	{
		$result = $this->db->query("SELECT * FROM ipblock WHERE ipv4 = '".$ipv4."' and counter > 2");
		foreach($result as $row)
		{
			// IP still blocked
			if (date("U") < $row['time']+IP_BLOCK_TIME)
			{
				return true;
			}
			else
			{
				return false;
			}
		}
		return false;
	}

	public function blockIPv4($ipv4)
	{
		$result = $this->db->query('SELECT * FROM ipblock');
		$match = false; $cnt = 1;
		foreach($result as $row)
		{
			if (strcmp($row['ipv4'],$ipv4)==0) { $match = true; $cnt = $row['counter']; $cnt++; }
		}
		if ($match)
		{
			$this->db->exec("UPDATE ipblock SET time = '".date("U")."', counter = '".$cnt."' WHERE ipv4 = '".$ipv4."';");
		}
		else
		{
			$this->db->exec("INSERT INTO ipblock (time,ipv4,counter) VALUES ('".date("U")."','".$ipv4."','".$cnt."');");
		}
	}

	public function unblockAll()
	{
		$this->db->exec("DELETE from ipblock");
	}

	public function updateOnlineStatusOnAllDevice()
	{
		try
		{
			// update online field after device was not online 3x KEEPALIVE_TIME
			$result = $this->db->query("SELECT id, uid, lastupdate FROM device ORDER BY lastupdate DESC");// ORDER BY name ASC";
			// current unixtimestamp
			$timeModifier = (KEEPALIVE_TIME) * 4;
			$currTime = (int)date("U")-$timeModifier;
			foreach($result as $row)
			{
				if ((int)$row['lastupdate'] < $currTime) { $this->db->exec("UPDATE device SET online = '0' WHERE uid='".$row['uid']."'"); }
			}
		}
		catch(PDOException $e)
		{
			$this->dbCatch++;
			if ($this->dbCatch > 5) { $this->response->back(NET_DATABASE_ERROR); }
			usleep(rand(10000,500000));
			$this->updateOnlineStatusOnAllDevice();
		}
	}

	public function newMessage($uidFrom,$uidTo,$cmd,$message)
	{
		try
		{
			$this->db->exec("INSERT INTO msg (uidFrom,uidTo,cmd,message,created,transmitted) VALUES ('".$uidFrom."','".$uidTo."','".$cmd."','".$message."','".date("U")."','0');");
			usleep(rand(1000,50000));
			//$this->logMessage("[".get_class($this)."] new message from UID[".$uidFrom." to UID[".$uidTo."]");
		}
		catch(PDOException $e)
		{
			$this->dbCatch++;
			if ($this->dbCatch > 5) { $this->response->back(NET_DATABASE_ERROR); }
			usleep(rand(10000,500000));
			$this->newMessage($uidFrom,$uidTo,$cmd,$message);
		}
	}

	public function getAllMessages()
	{	
		$message = array();
		$result = $this->db->query("SELECT * FROM msg ORDER by created desc LIMIT ".DISPLAY_LOG_ROWS);
		foreach($result as $row)
		{
			$tmpMsg = new cMessage;
			$tmpMsg->created     = $row['created'];
			$tmpMsg->fromUID     = $row['uidFrom'];			
			$tmpMsg->toUID       = $row['uidTo'];
			$tmpMsg->cmd         = $row['cmd'];
			$tmpMsg->message     = $row['message'];
			$tmpMsg->transmitted = $row['transmitted'];
			$messages[] = $tmpMsg;
		}
		return $messages;
	}

	public function checkPendingMessages(cDevice $myDevice)
	{
		// return true if there is an unread message
		$result = $this->db->query("SELECT uidFrom, uidTo, message FROM msg where uidTo = '".$myDevice->uid."' and transmitted = '0'");
		$match = false;
		foreach($result as $row)
		{
			if (strcmp($row['uidTo'],$myDevice->uid)==0) { $match = true; }
		}
		if ($match) { return true; }
		return false;
	}

	public function fetchPendingMessage(cDevice $myDevice)
	{
		// fetch message by message
		$result = $this->db->query("SELECT id, uidFrom, uidTo, cmd, message FROM msg where uidTo = '".$myDevice->uid."' and transmitted = '0'");
		$message = "";
		foreach($result as $row)
		{
			if (strcmp($row['uidTo'],$myDevice->uid)==0)
			{
				$pl = $this->getDeviceByUID($row['uidFrom']);
				$message = $pl->uid.";;".$pl->name.";;".$row['cmd'].";;".$row['message'];
				// update msg
				try
				{
					// update transmitted column
					$this->db->exec("UPDATE msg SET transmitted = '1' WHERE id = '".$row['id']."'");
					// or we could simply delete the message
				}
				catch(PDOException $e)
				{
					$this->response->back(NET_DATABASE_ERROR);
				}
				return $message;
			}
		}	
	}

	public function purgeMessage()
	{
		$this->db->exec("DELETE from msg");
	}


	public function getDevice($id)
	{
		$result = $this->db->query("SELECT * FROM device WHERE id = '".$id."'");
		foreach($result as $row)
		{
			$tmpDevice = new cDevice;
			$tmpDevice->id          = $row['id'];
			$tmpDevice->uid         = $row['uid'];
			$tmpDevice->upw         = $row['upw'];
			$tmpDevice->name        = $row['name'];
			$tmpDevice->ipv4        = $row['ipv4'];
			$tmpDevice->online      = $row['online'];
			$tmpDevice->description = $row['description'];
			$tmpDevice->created     = $row['created'];
			$tmpDevice->lastupdate  = $row['lastupdate'];
		}
		return $tmpDevice;
	}

	public function getDeviceByUID($uid)
	{
		$result = $this->db->query("SELECT * FROM device WHERE uid = '".$uid."'");
		foreach($result as $row)
		{
			$tmpDevice = new cDevice;
			$tmpDevice->id          = $row['id'];
			$tmpDevice->uid         = $row['uid'];
			$tmpDevice->upw         = $row['upw'];
			$tmpDevice->name        = $row['name'];
			$tmpDevice->ipv4        = $row['ipv4'];
			$tmpDevice->online      = $row['online'];
			$tmpDevice->description = $row['description'];
			$tmpDevice->created     = $row['created'];
			$tmpDevice->lastupdate  = $row['lastupdate'];
		}
		return $tmpDevice;
	}

	public function getAllDevices()
	{
		$device = array();
		$result = $this->db->query('SELECT * FROM device ORDER by name');
		foreach($result as $row)
		{
			$tmpDevice = new cDevice;
			$tmpDevice->id          = $row['id'];
			$tmpDevice->uid         = $row['uid'];			
			$tmpDevice->upw         = $row['upw'];
			$tmpDevice->name        = $row['name'];
			$tmpDevice->ipv4        = $row['ipv4'];
			$tmpDevice->online      = $row['online'];
			$tmpDevice->description = $row['description'];
			$tmpDevice->created     = $row['created'];
			$tmpDevice->lastupdate  = $row['lastupdate'];
			$device[] = $tmpDevice;
		}
		return $device;
	}
	
	public function getAllLog()
	{
		$log = array();
		$result = $this->db->query("SELECT * FROM log ORDER by time desc LIMIT ".DISPLAY_LOG_ROWS);
		foreach($result as $row)
		{
			$tmpLog = new cLog;
			$tmpLog->lDate = date("d.M.Y H:i",$row['time']);
			$tmpLog->message = $row['message'];
			$log[] = $tmpLog;
		}
		return $log;
	}

	public function getAllBlocked()
	{
		$block = array();
		$result = $this->db->query("SELECT * FROM ipblock ORDER by time desc LIMIT ".DISPLAY_LOG_ROWS);
		foreach($result as $row)
		{
			$tmpBlock = new cBlock;
			$tmpBlock->lDate = date("d.M.Y H:i",$row['time']);
			$tmpBlock->ipv4  = $row['ipv4'];
			$tmpBlock->counter = $row['counter'];
			$block[] = $tmpBlock;
		}
		return $block;
	}
	
	public function getNumberOfOnlineDevice()
	{
		$result = $this->db->query("SELECT COUNT(*) FROM device WHERE online = '1'");
		return $result->fetchColumn();
	}

	public function getNumberOfOfflineDevice()
	{
		$result = $this->db->query("SELECT COUNT(*) FROM device WHERE online = '0'");
		return $result->fetchColumn();
	}

	public function getNumberOfRegisteredDevice()
	{
		$result = $this->db->query("SELECT COUNT(*) FROM device");
		return $result->fetchColumn();
	}

	public function deleteDevice($id)
	{
		$this->db->exec("DELETE from device WHERE id = ".$id.";");
		$this->logMessage("[".get_class($this)."] deleted device with ID ".$id);
	}

	public function deviceExists($uid)
	{
		$result = $this->db->query("SELECT * FROM device WHERE uid = '".$uid."'");
		foreach($result as $row) { if (strcmp($row['uid'],$uid)==0) { return true; } }
		return false;
	}

	public function devicesOnline($uid)
	{
		$result = $this->db->query("SELECT * FROM device WHERE uid = '".$uid."'");
		foreach($result as $row) { if (strcmp($row['uid'],$uid)==0) { if ($row['online']==1) { return true;} else { return false;}  } }
		return false;
	}

	public function checkDevicePassword(cDevice $device)
	{
		$result = $this->db->query("SELECT * FROM device WHERE uid = '".$device->uid."'");
		foreach($result as $row) { if (strcmp($row['upw'],$device->upw)==0) { return true; } }
		return false;
	}

	public function saveDeviceFromUI($id,$descr,$secr)
	{
		$this->db->exec("UPDATE device SET description = '".$descr."', upw = '".$secr."' WHERE id = ".$id.";");
	}

	public function createDevice(cDevice $newDevice)
	{
		$this->db->exec("INSERT INTO device (uid,upw,name,ipv4,online,created,lastupdate) VALUES ('".$newDevice->uid."', '".$newDevice->upw."', '".$newDevice->name."','".$newDevice->ipv4."','".$newDevice->online."','".$newDevice->lastupdate."','".$newDevice->lastupdate."');");
		$this->logMessage("[".get_class($this)."] created new device called ".$newDevice->name." with UID[".$newDevice->uid."]");
	}

	public function updateDevice(cDevice $newDevice)
	{
		$this->db->exec("UPDATE device SET online = '".$newDevice->online."', lastupdate = '".$newDevice->lastupdate."' WHERE uid = '".$newDevice->uid."';");
	}

	public function loginDevice(cDevice $newDevice)
	{
		$this->db->exec("UPDATE device SET ipv4 = '".$newDevice->ipv4."', name = '".$newDevice->name."', online = '".$newDevice->online."', lastupdate = '".$newDevice->lastupdate."' WHERE uid = '".$newDevice->uid."';");
	}

	public function logoutDevice(cDevice $newDevice)
	{
		$this->db->exec("UPDATE device SET online = '".$newDevice->online."', lastupdate = '".$newDevice->lastupdate."' WHERE uid = '".$newDevice->uid."';");
	}
}

class cBlock
{
	public $lDate;
	public $ipv4;
	public $counter;
}

class cLog
{
	public $lDate;
	public $message;
}

class cMessage
{
	public $created;
	public $fromUID;
	public $toUID;
	public $message;
	public $transmitted;
}

// struct Device
class cDevice
{
	public $id;
	public $uid;
	public $upw;
	public $name;
	public $ipv4;
	public $description;
	public $online;
	public $lastupdate;
	
	public function generateUID()
	{
		// generate 128bit uid string in hex notation
		$this->uid = $this->genUuid();
		$this->uid = strtoupper($this->uid);
	}

	public function generatePassword()
	{
		// generate 128bit uid string in hex notation
		$this->upw = $this->genUuid();
		$this->upw = strtoupper($this->upw);
	}
	
	private function genUuid()
	{
		return sprintf( '%04x%04x%04x%04x%04x%04x%04x%04x',
			// 32 bits for "time_low"
			mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ),

			// 16 bits for "time_mid"
			mt_rand( 0, 0xffff ),

			// 16 bits for "time_hi_and_version",
			// four most significant bits holds version number 4
			mt_rand( 0, 0x0fff ) | 0x4000,

			// 16 bits, 8 bits for "clk_seq_hi_res",
			// 8 bits for "clk_seq_low",
			// two most significant bits holds zero and one for variant DCE1.1
			mt_rand( 0, 0x3fff ) | 0x8000,

			// 48 bits for "node"
			mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff ), mt_rand( 0, 0xffff )
		);
	}
}

class cRequest
{
	// Note: for some reason TARGET html5 and TARGET flash do not handle the SetHeader Content-Type: application/x-www-form-urlencoded
	// PHP populates the $_POST array with data, only when the Content-type is set to "application/x-www-form-urlencoded" or "multipart/form-data"
	// So we need to read from php://input and populate $_POST ... see __construst() ... may there is another workaround
	private $code;
	private $secret;
	private $uid;
	private $upw;
	private $deviceName;
	private $message;
	private $duid;
	private $ipv4;
	private $db;
	private $response;

	/**
	* constructor
	*
	* @return just instantiate the class
	*/
	function __construct()
	{
		// $_POST handling ...
		parse_str(file_get_contents("php://input"), $_POST);		
		// connect database
		$this->db       = new cDatabase();
		$this->response = new cResponse();
	}

	private function isClientRequest()
	{
		// every requests containing a HTTP POST from a client MUST implement at least an UID and a REQUEST-CODE
		if(isset($_POST['a']) && isset($_POST['i'])) { return true; }
		return false;
	}

	private function validateCode()
	{
		if (!$this->code==NET_GUEST_LOGIN || !$this->code==NET_LOGIN || !$this->code==NET_LOGOUT || !$this->code==NET_PING || !$this->code==NET_DEVICE_RENAME || !$this->code==NET_SEND_MESSAGE || !$this->code==NET_RETRIEVE_MESSAGE || !$this->code==NET_DEVICE_LIST || !$this->code==NET_SEND_HIGHSCORE || !$this->code==NET_RETRIEVE_HIGHSCORE)
		{
			$this->db->logMessage("[".get_class($this)."] unknown request from IP ".$this->ipv4."."); $this->db->blockIPv4($this->ipv4); $this->response->back(NET_REQUEST_UNKNOWN);
		}
	}

	private function validateUID()
	{
		if (!preg_match("/^0$|^[A-F0-9]{32}$/",$this->uid))
		{
			$this->db->logMessage("[".get_class($this)."] invalid UID in request from IP ".$this->ipv4.".");
			$this->db->blockIPv4($this->ipv4);
			$this->response->back(NET_UID_FORMAT_ERROR);
		}
	}

	private function validateDUID()
	{
		if (!preg_match("/^0$|^[A-F0-9]{32}$/",$this->duid))
		{
			$this->db->logMessage("[".get_class($this)."] invalid DUID in request from IP ".$this->ipv4.".");
			$this->db->blockIPv4($this->ipv4);
			$this->response->back(NET_UID_FORMAT_ERROR);
		}
	}

	private function validateDeviceName()
	{
		if (DEVICE_NAME_MAX_CHARS<DEVICE_NAME_MIN_CHARS) { $this->db->logMessage("[".get_class($this)."] invalid settings detected. Please check DEVICE_NAME_MAX_CHARS in your script."); }
		if (!preg_match("/^[A-Za-z0-9 \(\)\-]{".DEVICE_NAME_MIN_CHARS.",".DEVICE_NAME_MAX_CHARS."}$/",$this->deviceName))
		{
			$this->db->logMessage("[".get_class($this)."] invalid DeviceName in request from IP ".$this->ipv4.".");
			$this->response->back(NET_NAME_FORMAT_ERROR);
		}
	}

	private function validateMessage()
	{
		if (!preg_match("/[A-Za-z0-9 \;\(\)\-]{".MESSAGE_MIN_CHARS.",".MESSAGE_MAX_CHARS."}$/",$this->message))
		//if (!preg_match("/^[A-Za-z0-9 \(\)\-]{".MESSAGE_MIN_CHARS.",".MESSAGE_MAX_CHARS."}$/",$this->message))
		{
			$this->db->logMessage("[".get_class($this)."] invalid Message in request from IP ".$this->ipv4.".");
			$this->response->back(NET_MSG_FORMAT_ERROR);
		}
	}

	private function validateSecret()
	{
		// block ip on wrong secret
		if (strcmp($this->secret,NET_AUTO_REGISTER_SECRET)!==0)
		{
			$this->db->logMessage("[".get_class($this)."] could not register device from IP ".$this->ipv4." because of a wrong secret [".$this->secret."]");
			$this->db->blockIPv4($this->ipv4);
			$this->response->back(NET_SECRET_WRONG);
		}
	}
	
	private function validateSession()
	{
		session_start();
		if (($_SESSION['gcLoggedIn']==true) && ($this->db->deviceExists($_SESSION['gcUID'])))
		{
			return;
		}
		else
		{
			if ($this->db->deviceExists($_SESSION['gcUID'])) { $this->response->back(NET_PLAYER_LOGIN_FIRST); } else { $this->response->back(NET_DEVICE_UNKNOWN); }
		}
	}

	/**
	* preProcess - request
	*
	* @return
	*/
	public function preProcess()
	{
		// Process every request
		// read IPv4 address
		$this->ipv4 = $this->getIPv4();

		// IPv4 block list
		if ($this->db->isBlocked($this->ipv4)) { $this->db->logMessage("[".get_class($this)."] request from blocked IP ".$this->ipv4." ignored."); $this->db->blockIPv4($this->ipv4); $this->response->back(NET_IP_ADDR_BLOCKED); }

		// Update online status on all devices, had to be removed here
		//$this->db->updateOnlineStatusOnAllDevice();

		// clean up tasks (could be used to delete old devices)
		//$this->db->deleteStaleDevices();

		// client request, could be improved
		if ($this->isClientRequest())
		{
			$this->processClient();
		}
		// WebUI request
		else
		{
			if (UI_ENABLED) { $this->processUIClient(); }
		}
	}

	private function processClient()
	{
		// HTTP POST -> set defaults -> need sanity checks, may use filter_input but requires PHP5.2
		$this->code       = isset($_POST['a']) ? $_POST['a'] : NET_LOGIN; // an empty request code defaults to login
		$this->uid        = isset($_POST['i']) ? $_POST['i'] : "0";       // an empty UID defaults to 0
		$this->upw        = isset($_POST['p']) ? $_POST['p'] : "0";       // an empty password defaults to 0
		$this->secret     = isset($_POST['s']) ? $_POST['s'] : "0";       // an empty secret defaults to 0
		$this->deviceName = isset($_POST['n']) ? $_POST['n'] : "unknown"; // an empty device name defaults to unknown
		$this->message    = isset($_POST['m']) ? $_POST['m'] : "";        // an empty message
		$this->cmd        = isset($_POST['c']) ? $_POST['c'] : "";        // an empty command
		$this->duid       = isset($_POST['d']) ? $_POST['d'] : "0";       // an empty destination UID defaults to 0
		$this->uid        = strtoupper($this->uid);                       // uppercase UID
		$this->upw        = strtoupper($this->upw);                       // uppercase PASSWORD

		// validations: every request MUST contain a valid request code, uid, secret. more validations depend on specific request code
		$this->validateCode();
		$this->validateUID();
		$this->validateSecret();

		// process request code ... see REQUEST CODES
		switch ($this->code)
		{
			// NET_GUEST_LOGIN reuqest launches a poor login procedure, unknown/new devices (using an empty UID or UID of 0 in HTTP POST request)
			// receive an UID and PASSWORD (UPW) and will be auto registered. note only a small number of device will be autoregistered
			case NET_GUEST_LOGIN:
				// bail out if guest login not enabled
				if (!NET_AUTO_REGISTER_ENABLED) { $this->db->logMessage("blocked device from IP ".$this->ipv4.". guest login not enabled."); $this->db->blockIPv4($this->ipv4); $this->response->back(NET_GUEST_LOGIN_OFF); }
				// bail out if no secret is found in request
				if ($this->secret=="0") { $this->db->logMessage("blocked unknown device from IP ".$this->ipv4." from registering or using guest login. no secret provided."); $this->db->blockIPv4($this->ipv4);	$this->response->back(NET_SECRET_REQUIRED); }
				// block ip on wrong secret
				if (strcmp($this->secret,NET_AUTO_REGISTER_SECRET)!==0)
				{
					$this->db->logMessage("[".get_class($this)."] could not register device from IP ".$this->ipv4." because of a wrong secret [".$this->secret."]");
					$this->db->blockIPv4($this->ipv4);
					$this->response->back(NET_SECRET_WRONG);
				}
				$this->validateDeviceName(); // validate devices name
				$myDevice = new cDevice(); $myDevice->uid = $this->uid; $myDevice->upw = $this->upw; $myDevice->name = $this->deviceName; $myDevice->ipv4 = $this->ipv4; $myDevice->online = "1"; $myDevice->lastupdate = date("U");
				// auto register device with UID of 0
				if ($this->uid=="0")
				{
					$myDevice->generateUID();
					$myDevice->generatePassword();
					if ($this->db->getNumberOfRegisteredDevice() < MAX_REGISTERED_DEVICE)
					{
						$this->db->createDevice($myDevice);
						session_start(); $_SESSION['gcLoggedIn'] = true; $_SESSION['gcUID'] = $myDevice->uid;
						// Update online status on all devices
						$this->db->updateOnlineStatusOnAllDevice();
						// create response, send new UID, new UPW (Password), keepAliveTimer, MEssage of the day, devices and PHP session id
						$this->response->back(NET_REQUEST_OK,$myDevice->uid.";;".$myDevice->upw.";;".KEEPALIVE_TIME.";;".SRV_MOTD.";;".$this->db->getNumberOfOnlineDevice().";;".$this->db->getNumberOfOfflineDevice().";;".session_id().";;".MINIHOMENET_VERSION.";;".date("U"));
					}
					else
					{
						$this->db->logMessage("[".get_class($this)."] maximum number of registered devices reached. Cannot add new device from IP ".$this->ipv4);
						$this->response->back(NET_SERVER_MAX_PLAYER);
					}
				}
				// login when already registered
				if ($this->db->deviceExists($myDevice->uid))
				{
					// check password
					if ($this->db->checkDevicePassword($myDevice)) { $this->db->loginDevice($myDevice);	} else { $this->response->back(NET_SECRET_WRONG); }					
				}
				else
				{
					$this->db->logMessage("[".get_class($this)."] login request from unknown UID[".$myDevice->uid."] from IP ".$this->ipv4);
					$this->db->blockIPv4($this->ipv4);
					$this->response->back(NET_DEVICE_UNKNOWN);
				}
				// message
				$this->db->logMessage("[".get_class($this)."] login request from device ".$myDevice->name." UID[".$myDevice->uid."] from IP ".$this->ipv4."");
				session_start(); $_SESSION['gcLoggedIn'] = true; $_SESSION['gcUID'] = $myDevice->uid;
				// response
				$this->response->back(NET_REQUEST_OK,$myDevice->uid.";;".$myDevice->upw.";;".KEEPALIVE_TIME.";;".SRV_MOTD.";;".$this->db->getNumberOfOnlineDevice().";;".$this->db->getNumberOfOfflineDevice().";;".session_id().";;".MINIHOMENET_VERSION.";;".date("U"));

			// standard login procedure (NOT IMPLEMENTED)
			case NET_LOGIN:
				break;

			case NET_LOGOUT:
				$this->validateSession();
				$myDevice = new cDevice(); $myDevice->online = "0"; $myDevice->lastupdate = date("U"); $myDevice->uid = $_SESSION['gcUID'];
				$this->db->logMessage("[".get_class($this)."] logout request from device UID[".$_SESSION['gcUID']."]");
				$this->db->logoutDevice($myDevice);
				session_unset(); session_destroy();
				// Update online status on all device
				$this->db->updateOnlineStatusOnAllDevice();
				$this->response->back(NET_REQUEST_OK);
				break;

			case NET_PING:
				$this->validateSession();
				$myDevice = new cDevice(); $myDevice->online = "1"; $myDevice->lastupdate = date("U"); $myDevice->uid = $_SESSION['gcUID'];
				$this->db->updateDevice($myDevice);
				if ($this->db->checkPendingMessages($myDevice)) { $this->response->back(NET_MSG_AWAITING); }
				$this->response->back(NET_REQUEST_OK,$this->db->getNumberOfOnlineDevice().";;".$this->db->getNumberOfOfflineDevice().";;".date("U"));
				break;

			case NET_DEVICE_LIST:
				$this->validateSession();
				$this->db->updateOnlineStatusOnAllDevice(); $device = $this->db->getAllDevices(); $tmpStr="";
				if (sizeOf($device)>0) { foreach($device as $row) { $tmpStr = $tmpStr.".".$row->uid.",".$row->name.",".$row->online; } }
				$this->response->back(NET_REQUEST_OK,$tmpStr);
				break;

			case NET_SEND_MESSAGE:
				$this->validateSession(); $this->validateDUID(); $this->validateMessage();
				$this->db->newMessage($this->uid,$this->duid,$this->cmd,$this->message);
				$this->response->back(NET_REQUEST_OK);
				break;

			case NET_RETRIEVE_MESSAGE:
				$this->validateSession();
				$myDevice = new cDevice(); $myDevice->online = "1"; $myDevice->lastupdate = date("U"); $myDevice->uid = $_SESSION['gcUID'];
				$message = $this->db->fetchPendingMessage($myDevice);
				$this->response->back(NET_EXEC_MESSAGE,$message);
				break;

			default:
				$this->db->logMessage("[".get_class($this)."] device with IP ".$this->ipv4." blocked because of unknown code [".$this->code."]"); $this->db->blockIPv4($this->ipv4); 
				$this->response->back(NET_REQUEST_UNKNOWN);
		}
	}

	private function processUIClient()
	{
		// WebUI access
		session_start();
		$html = new cHTML;
		// Update online status on all device
		$this->db->updateOnlineStatusOnAllDevice();
		// Login request
		if (isset($_POST['P_PASSWORTVAL']))
		{
				$thispw = new cLogin;
				if ($thispw->validateUIPassword($_POST['P_PASSWORTVAL']))
				{
					$this->db->logMessage("[".get_class($this)."] successful login to UI");
				}
				else
				{
					$this->db->logMessage("bad login attempt to WebUI from IP: ".$this->ipv4); $this->db->blockIPv4($this->ipv4); $html->showLogin(); exit();
				}
		}
		if (!isset($_SESSION['loggedIn'])) { $html->showLogin(); exit(); }
		// save Device settings from UI
		if (isset($_POST['P_DESCRIPTION'])||isset($_POST['P_UPW'])) { $this->db->logMessage("[".get_class($this)."] changed settings for device with id ".$_POST['P_ID']." from UI"); $this->db->saveDeviceFromUI($_POST['P_ID'],$_POST['P_DESCRIPTION'],$_POST['P_UPW']); }
		// control
		if (isset($_POST['P_CMD'])||isset($_POST['P_CMD_ARG'])) { $this->db->logMessage("[".get_class($this)."] created MSG ".$_POST['P_CMD']." for uid ".$_POST['P_UID']." from UI"); $this->db->newMessage("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",$_POST['P_UID'],$_POST['P_CMD'],$_POST['P_CMD_ARG']); }
		// delete Device from UI
		if (isset($_GET['del'])) { $this->db->deleteDevice($_GET['del']); }
		// delete Log from UI
		if (isset($_GET['purgeLog'])) { $this->db->purgeLog(); }	
		// unblock all from UI
		if (isset($_GET['unblockAll'])) { $this->db->unblockAll(); }	
		// delete Message from UI
		if (isset($_GET['purgeMessage'])) { $this->db->purgeMessage(); }	
		// display page according HTTP GET page variable
		if(isset($_GET['page']))
		{
			// display device
			if ($_GET['page']=="device")
			{
				$alldevices = $this->db->getAllDevices();
				$html->showDevice($alldevices);
			}
			// control device
			if ($_GET['page']=="deviceCrtl")
			{
				$device = $this->db->getDevice($_GET['id']);
				$html->crtlDevice($device);
			}
			// edit device
			if ($_GET['page']=="deviceEdit")
			{
				$device = $this->db->getDevice($_GET['id']);
				$html->editDevice($device);
			}
			// display log
			if ($_GET['page']=="log")
			{
				$html->showLog($this->db->getAllLog(),$this->db->getAllBlocked(),$this->db->getAllMessages());
			}
			// display about
			if ($_GET['page']=="about")
			{
				$html->showAbout();
			}
			// logout
			if ($_GET['page']=="logout")
			{
				session_unset(); session_destroy();
				$html->showLogin();
				$this->db->logMessage("[".get_class($this)."] logged out from UI. IP: ".$this->ipv4);
			}
		}
		else
		{
			// default page
			$alldevices = $this->db->getAllDevices();
			$html->showDevice($alldevices);
		}
	}

	private function getIPv4()
	{
		if (!empty($_SERVER['HTTP_CLIENT_IP']))
		return $_SERVER['HTTP_CLIENT_IP'];
		elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR']))
		return $_SERVER['HTTP_X_FORWARDED_FOR'];
		else
		return $_SERVER['REMOTE_ADDR'];
	}
}

class cResponse
{
	/**
	* constructor
	*/
	public function back($code,$data="")
	{
		exit(htmlspecialchars($code.";;".$data));
	}
}

class cLogin
{
	public function validateUIPassword($pw)
	{
		if (strcmp($pw,UI_PASSWORD)==0) { $_SESSION['loggedIn']=true; return true; }
		return false;
	}
}

class cHTML
{
	// CSS originally from http://unraveled.com/publications/assets/css_tabs/index4.html
	// repeating things
	private $pageHeader = "<!DOCTYPE HTML>\n<head>\n<title>miniHomeNet server :: administration</title>\n<meta name=\"author\" content=\"dumplab\" />\n<meta http-equiv=\"pragma\" content=\"no-cache\" />\n<meta http-equiv=\"Content-type\" content=\"text/html; charset=iso-8859-1\" />\n<style type=\"text/css\">body {font: 0.8em/1.5 \"arial\",sans-serif; text-align: left;}ul#tabnav { text-align: left; margin: 1em 0 1em 0; font: bold 11px verdana, arial, sans-serif; border-bottom: 1px solid #007799; list-style-type: none; padding: 3px 10px 3px 10px; } ul#tabnav li { display: inline; } body#tab1 li.tab1, body#tab2 li.tab2, body#tab3 li.tab3, body#tab4 li.tab4 { border-bottom: 1px solid #fff; background-color: #fff; } body#tab1 li.tab1 a, body#tab2 li.tab2 a, body#tab3 li.tab3 a, body#tab4 li.tab4 a { background-color: #fff; color: #000; position: relative; top: 1px; padding-top: 4px; } ul#tabnav li a { padding: 3px 4px; border: 1px solid #007799; background-color: #CCF; color: #666; margin-right: 0px; text-decoration: none; border-bottom: none; } ul#tabnav a:hover { background: #fff; } .rowA {	background-color: #efefef; color: inherit; } .rowB { background-color: #fafafa; color: inherit; }\n</style></head>\n";
	private $pageNavi   = "<ul id=\"tabnav\">\n<li class=\"tab1\"><a href=\"minihomenet.php?page=device\">Device</a></li>\n<li class=\"tab2\"><a href=\"minihomenet.php?page=log\">Log</a></li>\n<li class=\"tab3\"><a href=\"minihomenet.php?page=about\">About</a></li>\n<li class=\"tab4\"><a href=\"minihomenet.php?page=logout\">Logout</a></li>\n</ul>\n";
	private $pageFooter = "<p><abbr title=\"version 0.16\">miniHomeNet::administration</abbr></p>\n</body>\n</html>";
	private $pageTitle  = "<h1 style=\"display: inline;\">miniHomeNet</h1>\n";
	// images
	private $imgLogo    = "<img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABQAAAAUCAYAAACNiR0NAAAA5ElEQVQ4je3TPUpDQRTF8d8C/AiYVGnFWAquIYiQwgUoWlpYWKawtLA3SDagCxDssgALFxDBoIWidhaWihZe4REnz3mCXQ4cuHfuuf8phmGq/9I22iXzNWxVAV6gi2Zi1sQBzqsAYQ8vifNX7FaFneAabxiM+R1DHOeA5rGDu1g6w8eYT+OyUWTnyoDLhcUeagngDPqFfnES7CixnOvDScBHbOI2AzKK7HMZcBj1Fe79fJBvP+Aysje5wF4qFOrnAGfRiLqOfTyF19Ep9BtYiGwjdn/Vqq/f0sUSWoV+JQcw1d/0CZGCVa5rz/KiAAAAAElFTkSuQmCC\" alt=\"miniHomeNet\" title=\"miniHomeNet\" style=\"display: inline;\" />";
	private $imgOnline  = "<img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAB9klEQVQ4jWNgwAJqVoUqNq6K7GpaFfGweVXEk6ZVEZMbVoVqYVOLAcoX+crVLw39v+309P+3nhz+f/vpkf+7zs3537gs/H/tfH9dggYUz/RoX3u47//pmyv+7z0/8f+e8xP+n7yx9P/m41P/l8x0n0bQgMxu2+fbTk38v2x/KQrecWbS/8wem28EDYirN3w+eX3y/0kb4tFwwv/YOkPCBgQWqrTn9tn+r1vogYLz+23+BxWqziRogEucoJxXuvT/mHqN/xn9hv8zJxj+j2vU/O+VIfPfNVXUgKABNUuCQoqnux+LrtH775Ys/t81Sex/eLnWv7yJzsfrlgQF4tRYPtOFv3yO77QZW0v+H7+29v+jV+fg+OHLM/+PXl39f/qW4v/lc3ynhYYyMGMYkD/FZdri3U3/z9/d9H/PuUn/Nxyrh+ONxxr+7zk/+f+Fu5v+z9te8z9/igtqdKZ3WaV1LEn6v/fC7P8LdxfgxQcuzv/fOD/6f2qnVSzcgLh6g/NrDnZhiTrsePX+7v+xdYbH4AaEFqv96V8X/795qS9ReOK6xP+hxWqINOGdKfu2aIbd/5JZxOHi6fb/vbPkniPiPlG4JaRU+X96v/7/jIkGeHFav/7/kFLl/87xInUoAWkbydtrG8n7zS6K7z9eHMn32TaStwumDwBqV4m2UxaQvwAAAABJRU5ErkJggg==\" alt=\"online\" title=\"online\" />";
	private $imgOffline = "<img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAB3klEQVQ4jZWPTUiTARjHf+/evdOaNRtruoFZ4Q4rtGR0qSnI2KFb0deMQbOIogYijA4JeSjJkD4OlUVgJhW5gsryUkIUCWWMoI9L0SASBxUdOkQt1r9Lhz6sd/2Pz//5/Xge+HcacFWPVoVa3pnumptA2Gb/l1QZgcZcZOiZ0q9Kil/Py6qLPAU85QqiVuKogpNS7a2SfLclZ/txAbFyBRGiPaJXoltin0RLr4CV5QpMzPmDhIdLRAui6YZwBa4CznIFABuBF1AxCnT/L9zRnOz5Gt97pohVfR5I4HAfwVExADjsYO+scHyqf0rKFqXEleeKHR5Tcvy1atfsEbDEThCr33VCXW+lznxJXdNSuiB15KXg9lMCdtgJ1gUyFxV/KbU9+SZP54gcy9YXWdQ6iXNOP7DQTrDWvXVAoZwUeiD5h/Mymjd8BjJ2IEAjgeWP3SfzmjcueS5/kfeONHdMMmKZIrD5b2CKSv85mlIfzP1v5Lokmbvvirq298amIVlnJefpklia/Ais+BM3Z9+n/ZGMA5LRJ7ElJyoXTACLgWOsviD6JGNnQbh8D2e6oI3IIbHtk1g1KFw11wD/j86B5cvSOiLqE9NgpWd+wvJmcYfvASnA/K0NAgeBhp+H3wF8RME9WTaQMQAAAABJRU5ErkJggg==\" alt=\"offline\" title=\"offline\" />";
	private $imgEdit    = "<img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAB2ElEQVQ4jZXRT0jTcQAF8Ofvl5ZFMAg0oRiM2ZKiQwVLWpC4TVzbWgeV/DsSHQhdfsgUtkOXOnQyQVD8i2FSucX8Q+SgdIXayqBciTsIlQeJsZRMDZyvw8au+/ru7wOPB6Ty7Bxypss1H/xlFz4PGA0aHCSvzPl5b2svJrgww/hILy23qzloKioUBoJWbTTqKmZ8pJfjN0pYoyi01zdQqLxUpfPM3SzkarOeK81XGVz+yrFIhDWKwndKTmYkUHosP2TTcqX2Mk22cl4zmjmx/I1r8438/gAMe+XMyGTZWd+tO430dPfQUmXl4hM9t1+ryFh3EvEIIMNGg8HhrGPEDW7PneHfKYlbweNp5L0IAgBhr5xGNickbr7MJZe0B0NC7YcYcYNbs6e4EZD4ezw7jSx4ZA46cUQY2ZhWMeaTGAskkdX72Ju6e/jHPUDKjLQl58Qnj/KXT+L6mMzdGd3+87bKRJ/thENozqw7iXx5lPVxbRTRWNi/99TbwiGX3S8EAMCbVpkvXPg3oFTy09BD/gyNsr+lekcY6DLnnu5vKP7T6XTsdzRVJB63N7HOWprI1CsAoAFwHsClbEBv0p2saLVcCdqvG6hWq8UuTUUFIA+AFkBRCtUAwH+mL/sJobshUgAAAABJRU5ErkJggg==\" alt=\"edit\" title=\"edit\" />";
	private $imgDelete  = "<img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAACxElEQVQ4jYWRS0hUcRTGz/UxXqdmRm0sMq3uVYfJO83VGXN8JJowUoGvgcFL4QsMoRa2c+UQWoskiGaTzOZvrqxNplEaloIPKpWroSiWmaCZoSK+XX0tEjFMPavDOZzf+c53iIhoyS0atu5kqOslMqMjYq1IZuu3M9Qlt2ggIqJJt2hYrcxWtx+UYvVuNhZuSAdCFm5IbLUyG1v3S7Fc6VQn3aKB5m+lqZu1pdgqd2Dbo2CxIh0zbvM+yIzbxBYq0rHtUbBZ7sBGbQnmKzJUmnKZ2K/COCwnE1ZdArY8CubK0/DNFbsL+eaKZT/L07DpUbDiErCY6ofZIjumCnfUjuVFs0nnSfx2EJYKBGx4FPwoS8FIjsi+5IjsR1kKNjwKFgsEzCX7YexaJEZyxH9VDl4/z0azjJhJIsznC1irVjBR7MBEsQNr1Qrm8wVMJ3EYcp7GwNWz//epxxnFBjPC8D2RMJsnYKVawUq1gtk8AV8vcfh45RR6nFGHf6ojK4L1XQ7BuJ0wnStgOlfAaCKHrvRwdGRGHPlmakkLZ+2pJzBk4zBsIwzbCKqNQ1tqGJpTww8HvHCEsRZHCD4ncBiIJ3xK4NAfT+jfyZuTQtDkCPs/pNGuZy/senTLHPpkQrfM4blNh5cJWvTKhN6dWpNNhwab/l+IT9axRvkYPlgJXVbCeyvhmXwMPlnHfLKONVl5dFoJnXt6Ty/q/kK8cVrmswSjzUJ4ZyG8tRB8Eg+vpN3d4o3TsgZJg3YLod1CeGMh1Es8HsdpGdWZglSfOQCvJcIrieA1a1Bn0uy7s86kYfXmALRKhFaJUG8OwMNYjUpVIhlqxUDVG+uHumh/1IiBBzpdIwayRzH+eBLjh3tCgFolkoF4nj9nNoZkFkUGf715JqhVr9fHEFEoEXF7Zo/zPH/OaDTaCyO1bcURmvELBq2NiEL/AJqcVWtElFD0AAAAAElFTkSuQmCC\" alt=\"delete\" title=\"delete\" />";
	private $imgCrtl    = "<img src=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAIAAACQkWg2AAAACXBIWXMAAAsTAAALEwEAmpwYAAABaElEQVR4nIVRwUrDQBCdWSMYbVIrWiEIXgSTg6cepCf/wFPxUzzkDzyVnvwRP8CCIq2HXIoYeqi09FBJ2q0E0+w2WQ+RNYnWvtPu2/fmzeygoiiWZem6Duswm81c91WxLMs0zbVqADAMY7lcEk3TJMUYE0LIqxAiiiJCiGQ0TSPZGv1+HwCkgnPe6/VKpVJWoxRyZUK9Xm80GowxVVWTJLFte7FY/GGQ4JwHQZD2mS2UMwghEDE9TyaTx6fneYibyXxnW43juGhAREIIIqae0Wj09h4OK1fRw615clScoVqttlotyTabzW63CwD6ce0gOE+CcdHAGHMcJ80BAEqpVOxWdqe/DWEYttvtabzP6PBwT/U8b9VnfBuiKOp0Ot6pPb6/OzNEdlkAmDXkFqdsabWLy7x6RUIK/eUmBiavG2xaca5p/JFLyM5HOBX88+dRJIT5ScwlQSlVXNdFxHK5/E8bKXzfHwwGX19HotOv0ch0AAAAAElFTkSuQmCC\" alt=\"control\" title=\"control\" />";
	
	public function showLogin()
	{
		echo $this->pageHeader;
		echo "<body id=\"tab1\">\n";
		echo "<form action=\"minihomenet.php\" method=\"post\"><p>&nbsp;<input type=\"password\" name=\"P_PASSWORTVAL\" size=\"10\" maxlength=\"10\" alt=\"".SRV_MOTD."\" autofocus />&nbsp;<input type=\"submit\" id=\"search-submit\" value=\"Go\"  /></p></form>\n";
		echo "</body></html>\n";
	}

	public function crtlDevice($device)
	{
		echo $this->pageHeader;
		echo "<body id=\"tab1\">\n";
		echo $this->pageTitle."".$this->imgLogo;
		echo $this->pageNavi;
		echo "<h2>Control device ".$device->name."</h2>\n";
		echo "<form action=\"minihomenet.php\" method=\"post\">\n";
		echo "<input type=\"hidden\" name=\"P_UID\" value=\"".$device->uid."\" />\n";
		echo "<table border=\"0\">";
		echo "<tr class=\"rowA\"><td><abbr title=\"Device Name\">Name</abbr></td><td><abbr title=\"Commands are accepted by devices having MINIHOMENET_ALLOW_CMDS set to true\">Command</abbr></td><td>Arguments</td><td>Action</td></tr>"; $aCnt=0;
		echo "<td>".$device->name."</td>";
		echo "<td><select name=\"P_CMD\"><option value=\"".EXEC_PRINT_MESSAGE."\">PRINT MESSAGE</option><option value=\"".EXEC_STOP_SCRIPT."\">STOP SCRIPT</option><option value=\"".EXEC_REMOTE_COMMAND."\">REMOTE COMMAND</option><option value=\"".EXEC_SHUTDOWN_SYSTEM."\">SHUTDOWN SYSTEM</option></select></td>";
		echo "<td><input type=\"text\" name=\"P_CMD_ARG\" size=\"40\" maxlength=\"40\" alt=\"Enter arguments\" placeholder=\"enter optional arguments\" /></td>";
		echo "<td><input type=\"submit\" class=\"submit\" value=\"Send\" alt=\"Press this button to send command to the device\" /></td>\n";
		echo "</tr>\n";
		echo "</table>";
		echo "</form>\n";
		echo $this->pageFooter;
	}

	public function editDevice($device)
	{
		echo $this->pageHeader;
		echo "<body id=\"tab1\">\n";
		echo $this->pageTitle."".$this->imgLogo;
		echo $this->pageNavi;
		echo "<h2>Edit device ".$device->name."</h2>\n";
		echo "<form action=\"minihomenet.php\" method=\"post\">\n";
		echo "<input type=\"hidden\" name=\"P_ID\" value=\"".$device->id."\" />\n";
		echo "<table border=\"0\">";
		echo "<tr class=\"rowA\"><td>Id</td><td><abbr title=\"Unique UID\">UID</abbr></td><td><abbr title=\"Device Name\">Name</abbr></td><td><abbr title=\"Changing the password also requires a password change on the client. Otherwise client cannot login anymore\">Password</abbr></td><td>Description</td><td>Action</td></tr>"; $aCnt=0;
		echo "<tr class=\"rowB\"><td>".$device->id."</td>";
		echo "<td>".$device->uid."</td>";
		echo "<td>".$device->name."</td>";
		echo "<td><input type=\"text\" name=\"P_UPW\" size=\"30\" maxlength=\"30\" alt=\"Enter a password or leave blank\" placeholder=\"using basic password\" value=\"".$device->upw."\" /></td>";
		echo "<td><input type=\"text\" name=\"P_DESCRIPTION\" size=\"40\" maxlength=\"40\" alt=\"Enter a description\" placeholder=\"enter a useful description\" value=\"".$device->description."\" /></td>";
		echo "<td><input type=\"submit\" class=\"submit\" value=\"Save\" alt=\"Press this button to submit settings\" /></td>\n";
		echo "</tr>\n";
		echo "</table>";
		echo "</form>\n";
		echo $this->pageFooter;
	}

	public function showDevice($device)
	{
		echo $this->pageHeader;
		echo "<body id=\"tab1\">\n";
		echo $this->pageTitle."".$this->imgLogo;
		echo $this->pageNavi;
		echo "<h2>Registered devices</h2>\n";
		if (sizeOf($device)>0)
		{
			echo "<table border=\"0\">";
			echo "<tr class=\"rowA\"><td><strong>ID</strong></td><td><strong>Name</strong></td><td><strong>IPv4</strong></td><td><strong>Description</strong></td><td><strong>Created</strong></td><td><strong>Last Update<strong></td><td><strong>Online</strong></td><td>&nbsp;</td><td>&nbsp;</td><td>&nbsp;</td></tr>"; $aCnt=0;
			foreach($device as $row)
			{
				if ($aCnt % 2){$bg = "A";}else{$bg = "B";} ; $aCnt++;
				echo "<tr class=\"row".$bg."\">";
				echo "<td>".$row->id."</td>";
				echo "<td><abbr = title=\"UID:".$row->uid."\">".$row->name."</abbr></td>";
				echo "<td>".$row->ipv4."</td>";
				echo "<td>".$row->description."</td>";
				echo "<td>".date("d.M.Y H:i",$row->created)."</td>";
				echo "<td>".date("d.M.Y H:i",$row->lastupdate)."</td>";
				if ($row->online=="1") { echo "<td>".$this->imgOnline."</td>"; } else { echo "<td>".$this->imgOffline."</td>"; }				
				echo "<td><a href=\"minihomenet.php?page=deviceCrtl&id=".$row->id."\">".$this->imgCrtl."</a></td>\n";
				echo "<td><a href=\"minihomenet.php?page=deviceEdit&id=".$row->id."\">".$this->imgEdit."</a></td>";
				echo "<td><a href=\"minihomenet.php?del=".$row->id."\">".$this->imgDelete."</a></td>\n";
				echo "</tr>\n";
			}
			echo "</table>";
			echo "<p>Found ".$aCnt." device.</p>\n";
		}
		echo $this->pageFooter;
	}

	public function showLog($log,$block,$msg)
	{
		echo $this->pageHeader;
		echo "<body id=\"tab2\">\n";
		echo $this->pageTitle."".$this->imgLogo;
		echo $this->pageNavi;
		echo "<h2>Messages</h2>\n";
		if (sizeOf($msg)>0)
		{
			echo "<table border=\"0\">";
			echo "<tr class=\"rowA\"><td><strong>Date created</strong></td><td><strong>command</strong><td><strong>arguments</strong></td><td><strong>transmitted</strong></td></tr>"; $aCnt=0;
			foreach($msg as $row)
			{
				if ($aCnt % 2){$bg = "A";}else{$bg = "B";} ; $aCnt++;
				echo "<tr class=\"row".$bg."\">";
				echo "<td><abbr title=\"from ".$row->fromUID." to ".$row->toUID."\">".date("d.M.Y H:i",$row->created)."</abbr></td>";
				$cmdString = "UNKNOWN";
				if ($row->cmd=="0800") { $cmdString = "EXEC_PRINT_MESSAGE"; }
				if ($row->cmd=="0801") { $cmdString = "EXEC_SHUTDOWN_SYSTEM"; }
				if ($row->cmd=="0802") { $cmdString = "EXEC_STOP_SCRIPT"; }
				if ($row->cmd=="0803") { $cmdString = "EXEC_REMOTE_COMMAND"; }
				echo "<td><abbr title=\"Exec-Code: ".$row->cmd."\">".$cmdString."</abbr></td>";
				echo "<td>".$row->message."</td>";
				echo "<td>".$row->transmitted."</td>";
				echo "</tr>\n";
			}
			echo "</table>";
			echo "<p>Last ".$aCnt." messages.<a href=\"minihomenet.php?purgeMessage&page=log\">delete all messages</a></p>\n";
		}
		echo "<h2>Blocked IPv4-Addresses</h2>\n";
		if (sizeOf($block)>0)
		{
			echo "<table border=\"0\">";
			echo "<tr class=\"rowA\"><td><strong>Date</strong></td><td><strong>IPv4-Address</strong></td><td><strong><abbr title=\"this IPv4 address has been blocked n times\">Count</abbr></strong></td></tr>"; $aCnt=0;
			foreach($block as $row)
			{
				if ($aCnt % 2){$bg = "A";}else{$bg = "B";} ; $aCnt++;
				echo "<tr class=\"row".$bg."\">";
				echo "<td>".$row->lDate."</td>";
				echo "<td>".$row->ipv4."</td>";
				echo "<td>".$row->counter."</td>";
				echo "</tr>\n";
			}
			echo "</table>";
			echo "<p>Last ".$aCnt." blocked IPv4 addresses.<a href=\"minihomenet.php?unblockAll&page=log\">Unblock all</a></p>\n";
		}
		echo "<h2>Log</h2>\n";
		if (sizeOf($log)>0)
		{
			echo "<table border=\"0\">";
			echo "<tr class=\"rowA\"><td><strong>Date</strong></td><td><strong>Message</strong></td></tr>"; $aCnt=0;
			foreach($log as $row)
			{
				if ($aCnt % 2){$bg = "A";}else{$bg = "B";} ; $aCnt++;
				echo "<tr class=\"row".$bg."\">";
				echo "<td>".$row->lDate."</td>";
				echo "<td>".$row->message."</td>";
				echo "</tr>\n";
			}
			echo "</table>";
			echo "<p>Last ".$aCnt." log entries. <a href=\"minihomenet.php?purgeLog&page=log\">delete log</a></p>\n";
		}
		echo $this->pageFooter;
	}

	public function showAbout()
	{
		echo $this->pageHeader;
		echo "<body id=\"tab3\">\n";
		echo $this->pageTitle."".$this->imgLogo;
		echo $this->pageNavi;
		echo "<pre>";
		echo "<font color=\"#bf3f00\">           _       _ _    _                      _   _      _   </font>\n<font color=\"#bf3f00\">          (_)     (_) |  | |                    | \ | |    | |  </font>\n<font color=\"#c55000\"> _ __ ___  _ _ __  _| |__| | ___  _ __ ___   ___|  \| | ___| |_ </font>\n<font color=\"#cb6200\">| '_ ` _ \| | '_ \| |  __  |/ _ \| '_ ` _ \ / _ \ . ` |/ _ \ __|</font>\n<font color=\"#d68500\">| | | | | | | | | | | |  | | (_) | | | | | |  __/ |\  |  __/ |_ </font>\n<font color=\"#dc9600\">|_| |_| |_|_|_| |_|_|_|  |_|\___/|_| |_| |_|\___|_| \_|\___|\__|</font>\n<font color=\"#dc9600\">Version ".MINIHOMENET_VERSION." &copy; 2016 dumplab</font></pre>\n";
		echo "<h2>Purpose</h2>\n";
		echo "<pre>Using miniHomeNet you can\n";
		echo " * auto register devices using a basic secret\n";
		echo " * exchange messages and commands between devices\n";
		echo " * manage your devices with this simple WebUI\n\n";
		echo "Usage is simple. Copy minihomenet.php to your webserver and point your clients (file config.json) to the URL. F.E. http(s)://yourserver.com/minihomenet.php.</pre>\n";
		echo "<h2>About</h2>\n";
		echo "<pre>miniHomeNet is based on HTTP POST requests. There is no usage of JSON no XML.</pre>\n";
		echo "<h2>License</h2>\n";
		echo "<pre>This software is provided 'as-is', without any express or implied\nwarranty. In no event will the authors be held liable for any damages\narising from the use of this software.\n\nPermission is granted to anyone to use this software for any purpose,\nincluding commercial applications, and to alter it and redistribute it\nfreely.\n</pre>";
		echo $this->pageFooter;
	}
}

// miniHomeNet
$req = new cRequest();
$req->preProcess();
?>
