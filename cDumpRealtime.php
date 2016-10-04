<?php
/**
* Basic TCPDUMP class
* 
* This class provides some basic methods to display tcpdump output
* 
* You MAY chmod +s /usr/sbin/tcpdump to capture data using a different uid/gid
* 
* Licensed under The MIT License
* For full copyright and license information, please see the LICENSE.txt
* Redistributions of files must retain the above copyright notice.
*
* @author    dumplab
* @copyright 2016 dumplab.ch
* @version   $Id: cDumpRealtime.php,v 0.0.1 19.04.2014 08:35:20 kstadler Exp $;
* @license   http://www.opensource.org/licenses/mit-license.php MIT License
*/
class cDumpRealtime
{
	// documentation
	//http://www.toppa.com/2005/using-phps-program-execution-functions-for-sftp/
	//ajax
	//http://www.binarytides.com/ajax-based-streaming-without-polling/

	private $enableLogger;
	public $myLogger;
	public  $tcpdumppid;
	public  $debug;
	
	function __construct()
	{
		// set debugging off - default value
		$this->setDebugOff();
	}

	function __toString()
	{
		return "[".get_class($this)." $fritz_host=".$fritz_host.", $fritz_pass=".$fritz_pass."]";
	}

	/**
    * Enable logging database
	*
    * @return void
	* @access public
    */
	public function enableLogger($myLogger)
	{
		if ($myLogger) { $this->enableLogger = true; $this->myLogger = $myLogger; }
	}

	/**
    * Disable logging
	*
    * @return void
	* @access public
    */
	public function disableLogger()
	{
		$this->enableLogger   = false;
		$this->myLogger       = null;
	}

	/**
    * isLoggingEnabled - shall we log to mysql
	*
    * @return bool true or false
	* @access public
    */	
	public function isLoggerEnabled()
	{
		return $this->enableLogger;
	}

	/**
	* Start capturing
	* 
	* @param string $interface name
	* @param string $capturefilter
	* @return void
	*/
	public function capture($interface="eth0",$capturefilter="",$maxframes=1000,$resolve="")
	{
		$childPipes = array( 
		0 => array("pipe", "r"), // stdin is a pipe that the child will read from 
		1 => array("pipe", "w"), // stdout is a pipe that the child will write to 
		2 => array("pipe", "w"), // stderr is a pipe that the child will write to 
		);

		$length = 1024;

		$this->tcpdumppid = proc_open(CONFIG_TCPDUMP_BINARY_PATH." ".$resolve." -c ".$maxframes." -l -i ".$interface." ".$capturefilter,$childPipes, $parentPipes);

		if ($this->isLoggerEnabled()) { $this->myLogger->info(get_class($this).": Starting realtime capture on ".$interface." using capture filter: ".$capturefilter); }

		if ($this->debug) { echo get_class($this).": Starting capture (".$maxframes." Frames) on ".$interface." using capturefilter: ".$capturefilter."\n\n"; }

		if (is_resource($this->tcpdumppid))
		{
			sleep(1);
			
			stream_set_blocking($parentPipes[1], TRUE); 
			while (!feof($parentPipes[1]))
			{
				print(fgets($parentPipes[1],$length));
				// PUSH THE data out by all FORCE POSSIBLE
				ob_flush();
				flush();
			}
			if ($this->debug) { echo get_class($this).": Done\n"; }
		}
	}

	/**
	* Enable debugging
	* 
	* @return void
	*/
	public function setDebugOn()
	{
		// enable debug to print some things
		$this->debug = true;
	}

	/**
	* Disable debugging
	* 
	* @return void
	*/
	public function setDebugOff()
	{
		// disable debug (default)
		$this->debug = false;
	}
}
?>
