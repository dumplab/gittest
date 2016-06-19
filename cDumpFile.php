<?php
/**
* cDumpFile - file operations / basic Libpcap/WinPcap packet decoding
* 
* Licensed under The MIT License
* For full copyright and license information, please see the LICENSE.txt
* Redistributions of files must retain the above copyright notice.
*
* Libpcap/WinPcap File Format
* +---------------+---------------+-------------+---------------+-------------+-----+
* | Global Header | Packet Header | Packet Data | Packet Header | Packet Data | ... |
* +---------------+---------------+-------------+---------------+-------------+-----+
*
* @author    dumplab
* @copyright dumplab
* @license   http://www.opensource.org/licenses/mit-license.php MIT License
*/
class cDumpFile
{
	private $filename;
	private $fileHandle;
	private $fileSize;
	private $fileReadPointer;
	private $globalHeader;
	private $packetHeader;
	private $packetData;
	private $packetPseudoHeader;
	private $packetCounter;

	/*
	Usage:
	******
	# Example - Basic parsing a pcap file
	$myPCAP = new cDumpFile("tcpdupfile.cap");
	if ($myPCAP->openFile())
	{
		// get global header
		$globalHeader = $myPCAP->getGlobalHeader();
		// read 10 packets
		while (($myPCAP->readAndParseNextPacket()) && ($myPCAP->getPacketCounter() < 11))
		{
			// read and parse packet
			$pseudo = $myPCAP->getPacketPseudoHeader();
			// output findings
			print_r($pseudo);
		}
		$myPCAP->closeFile();
	}
	unset($myPCAP);
	*/
	
	function __construct($filename="")
	{
		$this->setFileName($filename);
		$this->fileHandle         = "";
		$this->fileSize           = "";
		$this->globalHeader       = array();
		$this->packetHeader       = array();
		$this->packetPseudoHeader = array();
		$this->packetCounter      = 0;
		// set debugging off - default value
	}

	function __toString()
	{
		return "[".get_class($this)." $fritz_host=".$fritz_host.", $fritz_pass=".$fritz_pass."]";
	}

	/**
    * SetDumpFile
	*
    * @param string $file is a file processed using tcpdump
    * @return void PID
	* @access public
    */
	public function setFileName($name)
	{
		$this->filename = $name;
	}

	/**
    * GetDumpFile
	*
    * @return string Dumpfilename
	* @access public
    */
	public function getFileName()
	{
		return $this->filename;
	}
	
	/**
    * getFileSize - return Size of current file in bytes (must be opened and valid)
	*
    * @return int FileSize
	* @access public
    */
	public function getFileSize()
	{
		if ($this->globalHeader->valid) { return $this->fileSize; }
		return 0;
	}

	/**
    * openFile - Open, Read and Parse global header of a Libpcap/WinPcap file - save results in $this->globalHeader
	*
	* @param  bool true to write, false to read
    * @return bool true on success
	* @access public
    */
	public function openFile($write=false)
	{
		if ($write)
		{
			// open file for writing
			$this->fileHandle = fopen($this->getFileName(),"w");
		}
		// read file
		else
		{
			if (!file_exists($this->getFileName()) || !is_file($this->getFileName())) { return false; }
			// get file size
			$this->fileSize   = filesize($this->getFileName());
			// open file binary for reading
			$this->fileHandle = fopen($this->getFileName(),"rb");
			// read globalHeader
			if ($this->fileHandle)
			{
				$this->readGlobalHeaderFromFile();	
				return $this->globalHeader->valid;
			}
			return false;
		}
	}

	/**
    * closeFile - close filehandle
	*
    * @return void
	* @access public
    */
	public function closeFile()
	{
		if ($this->getFileName() == "")
		{
			return 0;
		}
		// read globalHeader
		if ($this->fileHandle)
		{
			fclose($this->fileHandle);
			$this->fileHandle = "";
		}
	}
	
	/**
    * readGlobalHeaderFromFile - Read and parse global header of a Libpcap/WinPcap file
	*
    * @return void PID
	* @access private
    */
	private function readGlobalHeaderFromFile()
	{
		// read first 24 bytes
		$this->globalHeader = new pcap_hdr_s($this->fileHandle);
		// update file pointer
		$this->fileReadPointer = ftell($this->fileHandle);
	}
	
	/**
    * writeGlobalHeaderFromFile - Write global header to a file
	*
	* @param  array containing complete header
    * @return void PID
	* @access private
    */
	public function writeGlobalHeader($header)
	{
		fwrite($this->f, pack($this->u32, 0xa1b2c3d4));
		fwrite($this->f, pack($this->u16.$this->u16.$this->u32.$this->u32.$this->u32.$this->u32,
			$header['version_major'],
			$header['version_minor'],
			$header['thiszone'],
			$header['sigfigs'],
			$header['snaplen'],
			$header['network']));
	}
	
	/**
    * readPacketHeaderFromFile - Read and parse packet header of a Libpcap/WinPcap file
	*
    * @return void PID
	* @access public
    */
	private function readPacketHeaderFromFile()
	{
		unset($this->packetHeader);
		// read one packet header
		$this->packetHeader    = new pcaprec_hdr_s($this->fileHandle);
		// update file pointer
		$this->fileReadPointer = ftell($this->fileHandle);
	}
	
	/**
    * writePacketHeader - Write a packet header to a file
	*
	* @param  array containing complete header
    * @return void PID
	* @access public
    */
	public function writePacketHeader($head)
	{
		fwrite($this->f, pack($this->u32.$this->u32.$this->u32.$this->u32,
		$head['ts_sec'],
		$head['ts_usec'],
		$head['incl_len'],
		$head['orig_len']));
		fwrite($this->f, $head['data']); //$data
	}

	/**
    * readPacketDataFromFile - Read raw packet data of a Libpcap/WinPcap file
	*
    * @return bool true on success
	* @access private
    */
	private function readPacketDataFromFile()
	{
		unset($this->packetData);
		$this->packetData = fread($this->fileHandle,$this->packetHeader->incl_len);
		// update file pointer
		$this->fileReadPointer = ftell($this->fileHandle);
	}

	/**
    * readAndParseNextPacket - Read and parse a packet of a Libpcap/WinPcap file - this creates a pseudo header
	*
    * @return bool 
	* @access public
    */
	public function readAndParseNextPacket()
	{
		// read Packet Header
		$this->readPacketHeaderFromFile();
		// data available
		if ($this->packetHeader->incl_len > 0)
		{
			// increase packet counter
			$this->packetCounter++;
			// read and store raw data
			$this->readPacketDataFromFile();
			// intepret the ethernet frame (including payload)
			$eth = new ethernet_header($this->packetData,$this->packetHeader->incl_len);
			// parse packet data (basic)
			$this->packetPseudoHeader = new pseudo_header($this->packetHeader,$eth);
			// update file pointer
			$this->fileReadPointer    = ftell($this->fileHandle);
			return true;
		}
		return false;
	}

	/**
    * readAndParsePacketNumber - Read and parse a single packet out of a Libpcap/WinPcap file
	*
	* @params int packetnumber
    * @return bool 
	* @access public
    */
	public function readAndParsePacketNumber($number)
	{
		$this->packetCounter=0;
		do
		{
			$this->readPacketHeaderFromFile();

			if ($this->packetHeader->incl_len > 0)
			{
//				echo "Create pseudo ............ looking for numer".$number." rightno at number".$this->packetCounter."<br />";
				// increase packet counter
				$this->packetCounter++;
				// read and store raw data
				$this->readPacketDataFromFile();
				if ($this->packetCounter==$number)
				{
					// intepret the ethernet frame (including payload)
					$eth = new ethernet_header($this->packetData,$this->packetHeader->incl_len);
					// parse packet data (basic)
					$this->packetPseudoHeader = new pseudo_header($this->packetHeader,$eth);
					return true;
				}
				// update file pointer
				$this->fileReadPointer    = ftell($this->fileHandle);
			}
		} while ($this->packetHeader->incl_len > 0);
		return false;
	}
	
	/**
    * packetCounter - returns packetCounter
	*
    * @return in 
	* @access public
    */
	public function getPacketCounter()
	{
		return $this->packetCounter;
	}
	
	/**
    * getGlobalHeader - returns globalHeader array for printing
	*
    * @return array
	* @access public
    */
	public function getGlobalHeader()
	{
		return $this->globalHeader;
	}

	/**
    * getPacketPseudoHeader - returns PseudoHeader, see Class pseudo_header
	*
    * @return array
	* @access public
    */
	public function getPacketPseudoHeader()
	{
		return $this->packetPseudoHeader;
	}

	/**
    * getPacketData - returns Raw Packet Data
	*
    * @return array
	* @access public
    */
	public function getPacketData()
	{
		return $this->packetData;
	}
	
	/**
    * Delete single dump file
	*
	* @params filename
    * @return void
	* @access public
    */
	public function deleteDump($name)
	{
		if ($name<>"") { unlink($name); return true; } else { return false; }
	}

	/**
    * getNumberOfFrames - Count the number of frames found in a capturefile
	*
	* @params filename
    * @return int number
	* @access public
    */
	public function getNumberOfFrames()
	{
		if ($this->getFileName() == "")
		{
			return 0;
		}
		else
		{
			if (file_exists($this->getFileName()))
			{
				$cnt = 0;
				$fh = fopen($this->getFileName(),"rb");
				if($fh)
				{
					$size = filesize($this->getFileName());
					// read first 24 bytes
					$pcapGlobalHeader = new pcap_hdr_s($fh);
					if ($pcapGlobalHeader->network == 1)
					{
						do
						{
							$pcapPacketHeader = null;
							// read one packet header
							$pcapPacketHeader = new pcaprec_hdr_s($fh);
							if ($pcapPacketHeader->incl_len > 0)
							{
								$cnt++;
								// move to next
								$rubish = fread($fh,$pcapPacketHeader->incl_len);
							}
						} while (($pcapPacketHeader->incl_len > 0));
					}
				}
				return $cnt;
			}
			return 0;
		}
	}
	
	// mergecap *.cap -w - | tcpdump -n -r - -w test2.cap
}

// convert simple filter syntax
class SingleFilterExpression
{
	public $type;
	public $direction;
	public $protocol;
	public $address;
	public $valid;

	function __construct($aString)
	{
		$this->valid = false;
		$term = array();

		// divide string, we expect type/dir/proto
		$term = split(" ",$aString);

		// check and / or
		
		// HOST
		if (in_array("host",$term))
		{
			// host, we expect ip only for now
			$this->type     = "HOST";
			$this->protocol = "IP";
			// continue
			$key = 0;
			$key = array_search("host",$term);
			switch ($key)
			{
				case 0:
					// source and destination
					$this->direction = "ANY";

					// there must be an ip or host
					if (isset($term[1]))
					{
						if (preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/',$term[1])) { $this->address = $term[1];	}
					}
					$this->valid=true;
					break;

				case 1:
					// see what key 0 is
					if ($term[0]=="dst") { $this->direction = "DST"; }
					if ($term[0]=="src") { $this->direction = "SRC"; }
					// there must be an ip or host
					if (isset($term[2]))
					{
						if (preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/',$term[2])) { $this->address = $term[2]; }
					}
					$this->valid=true;
					break;
			}
		}
		
		// UDP
		if (in_array("udp",$term))
		{
			$this->protocol = "UDP";
			// continue
			$key = 0;
			$key = array_search("host",$term);
			switch ($key)
			{
				case 0:
					// source and destination
					$this->direction = "ANY";

					// there must be an ip or host
					if (isset($term[1]))
					{
						if (preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/',$term[1])) { $this->address = $term[1];	}
					}
					$this->valid=true;
					break;

				case 1:
					// see what key 0 is
					if ($term[0]=="dst") { $this->direction = "DST"; }
					if ($term[0]=="src") { $this->direction = "SRC"; }
					// there must be an ip or host
					if (isset($term[2]))
					{
						if (preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/',$term[2])) { $this->address = $term[2]; }
					}
					$this->valid=true;
					break;
			}
		}

		// TCP
		if (in_array("tcp",$term))
		{
			$this->protocol = "TCP";
			// continue
			$key = 0;
			$key = array_search("host",$term);
			switch ($key)
			{
				case 0:
					// source and destination
					$this->direction = "ANY";

					// there must be an ip or host
					if (isset($term[1]))
					{
						if (preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/',$term[1])) { $this->address = $term[1];	}
					}
					$this->valid=true;
					break;

				case 1:
					// see what key 0 is
					if ($term[0]=="dst") { $this->direction = "DST"; }
					if ($term[0]=="src") { $this->direction = "SRC"; }
					// there must be an ip or host
					if (isset($term[2]))
					{
						if (preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/',$term[2])) { $this->address = $term[2]; }
					}
					$this->valid=true;
					break;
			}
		}

		// ARP
		if (in_array("arp",$term))
		{
			$this->protocol = "ARP";
			// continue
			$key = 0;
			$key = array_search("host",$term);
			switch ($key)
			{
				case 0:
					// source and destination
					$this->direction = "ANY";

					// there must be an ip or host
					if (isset($term[1]))
					{
						if (preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/',$term[1])) { $this->address = $term[1];	}
					}
					$this->valid=true;
					break;

				case 1:
					// see what key 0 is
					if ($term[0]=="dst") { $this->direction = "DST"; }
					if ($term[0]=="src") { $this->direction = "SRC"; }
					// there must be an ip or host
					if (isset($term[2]))
					{
						if (preg_match('/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/',$term[2])) { $this->address = $term[2]; }
					}
					$this->valid=true;
					break;
			}
		}
	}
}


// ********************
// * PCAP file format *
// ********************
// pcap file header - 24 bytes
class pcap_hdr_s
{
	public  $magic_number; 	// magic number (either d4c3b2a1 or a1b2c3d4)
	public  $version_major; // major version number
	public  $version_minor; // minor version number
	public  $thiszone;      // GMT to local correction
	public  $sigfigs;       // accuracy of timestamps
	public  $snaplen;       // max length of captured packets, in octets
	public  $network;       // data link type
	public  $valid;

	function __construct($fh)
	{
		// seek at the beginning
		if ((0==ftell($fh)))
		{
			// read first 24 bytes
			$buffer = unpack("Nmagic_number/vversion_major/vversion_minor/lthiszone/Vsigfigs/Vsnaplen/Vnetwork",fread($fh,24));
			$this->magic_number  = dechex($buffer['magic_number']);
			// magic number and D/I/X and 802.3 Ethernet only
			if (($this->magic_number=="d4c3b2a1")||($this->magic_number=="a1b2c3d4")&&$this->globalHeader->network==1)
			{
				$this->valid = true;
				$this->version_major = $buffer['version_major'];
				$this->version_minor = $buffer['version_minor'];
				$this->thiszone      = $buffer['thiszone'];
				$this->sigfigs       = $buffer['sigfigs'];
				$this->snaplen       = $buffer['snaplen'];
				$this->network       = $buffer['network'];
			}
			else
			{
				$this->valid = false;
			}
		}
		else
		{
			$this->valid = false;
		}
    }
}

// pcap packet header - 16 bytes
class pcaprec_hdr_s
{
	public $ts_sec;   // timestamp seconds
	public $ts_usec;  // timestamp microseconds
	public $incl_len; // the number of bytes of packet data actually captured and saved in the file. This value should never become larger than orig_len or the snaplen
	public $orig_len; // the length of the packet as it appeared on the network when it was captured.

	function __construct($fh)
	{
		// read 16 bytes
		$buffer = unpack("Vts_sec/Vts_usec/Vincl_len/Vorig_len",fread($fh,16));
		if (feof($fh)) { return; }
		$this->ts_sec   = $buffer['ts_sec'];
		$this->ts_usec  = $buffer['ts_usec'];
		$this->incl_len = $buffer['incl_len'];
		$this->orig_len = $buffer['orig_len'];
	}
}

// ******************
// * basic headers  *
// ******************
class ethernet_header
{
	public $dstmac;  // 6byte destination mac address
	public $srcmac;  // 6byte source mac address
	public $type;    // 2/4byte type
	public $payload; // payload (passed to next layer)

	function __construct($packetData,$len)
	{
		// read 14 bytes
		//$buffer = unpack("Cdst1/Cdst2/Cdst3/Cdst4/Cdst5/Cdst6/Csrc1/Csrc2/Csrc3/Csrc4/Csrc5/Csrc6/vtype",fread($fh,14));
		//$this->dstmac = $buffer['dst1'].$buffer['dst2'].$buffer['dst3'].$buffer['dst4'].$buffer['dst5'].$buffer['dst6'];
		//$this->srcmac = $buffer['src1'].$buffer['src2'].$buffer['src3'].$buffer['src4'].$buffer['src5'].$buffer['src6'];
		// using dot notation for mac address, reading first 14 bytes
		$buffer = unpack("ndst1/ndst2/ndst3/nsrc1/nsrc2/nsrc3/ntype",$packetData);
		$this->dstmac = dechex($buffer['dst1']).".".dechex($buffer['dst2']).".".dechex($buffer['dst3']);
		$this->srcmac = dechex($buffer['src1']).".".dechex($buffer['src2']).".".dechex($buffer['src3']);
		$this->type   = $buffer['type'];
		// calculate payload from packet length incl_len
		$len = $len - 14;
		// store ethernet payload
		if ($len > 0)
		{
			//echo "size:".strLen($packetData);
			//$this->payload = mb_substr($packetData, 14);
			$this->payload = substr($packetData, 14);
		}
		else
		{
			$this->payload = "";
		}
	}
	
	public function typeToString()
	{
		switch ($this->type)
		{
			case 8:
				return "LLC";
				break;
		
			case 2048:
				return "IPv4";
				break;
			
			case 2054:
				return "ARP";
				break;
				
			case 2114:
				return "WOL";
				break;
				
			case 34939:
				return "HOMEPLUG";
				break;
			
			case 34525:
				return "IPv6";
				break;
				
			case 34887:
				return "MPLS";
				break;
				
			default;
				return "UNKNOWN";
		}
	}
}

class arp_header
{
	public $hwtype;
	public $prototype;
	public $hwsize;
	public $protosize;
	public $opcode;
	public $scrmac;
	public $srcip;
	public $dstmac;
	public $dstip;

	function __construct($arppacket)
	{
		// read 14 bytes
		//$buffer = unpack("Cdst1/Cdst2/Cdst3/Cdst4/Cdst5/Cdst6/Csrc1/Csrc2/Csrc3/Csrc4/Csrc5/Csrc6/vtype",fread($fh,14));
		//$this->dstmac = $buffer['dst1'].$buffer['dst2'].$buffer['dst3'].$buffer['dst4'].$buffer['dst5'].$buffer['dst6'];
		//$this->srcmac = $buffer['src1'].$buffer['src2'].$buffer['src3'].$buffer['src4'].$buffer['src5'].$buffer['src6'];
		// using dot notation
		$buffer = unpack("nhwtype/nprototype/Chwsize/Cprotosize/nopcode/nsrc1/nsrc2/nsrc3/Nsrcip/ndst1/ndst2/ndst3/Ndstip",$arppacket);
		$this->hwtype    = $buffer['hwtype'];
		$this->prototype = $buffer['prototype'];
		$this->hwsize    = $buffer['hwsize'];
		$this->protosize = $buffer['protosize'];
		$this->opcode    = $buffer['opcode'];
		$this->srcmac    = dechex($buffer['src1']).".".dechex($buffer['src2']).".".dechex($buffer['src3']);
		$this->srcip     = long2ip($buffer['srcip']);
		$this->dstmac    = dechex($buffer['dst1']).".".dechex($buffer['dst2']).".".dechex($buffer['dst3']);
		$this->dstip     = long2ip($buffer['dstip']);
//		$this->srcmac = dechex($buffer['src1']).".".dechex($buffer['src2']).".".dechex($buffer['src3']);
//		$this->type   = $buffer['type'];
//		$len = $len - 14;
		// store ethernet payload
//		if ($len > 0)
//		{
//			//echo "size:".strLen($packetData);
//			$this->payload = mb_substr($packetData, 14);
//		}
//		else
//		{
//			$this->payload = "";
//		}
	}
	
	public function hwTypeToString()
	{
		switch ($this->hwtype)
		{
			case 1:
				return "Ethernet";
				break;

			default;
				return "UNKNOWN";
		}
	}
}

class ipv4_header
{
	public $version;
	public $ihl;
	public $tos;
	public $srcip;
	public $dstip;
	public $proto;
	public $payload;

	function __construct($ippacket)
	{
		$buffer = unpack("Cversion_ihl/Cservices/nlength/nidentification/nflags_offset/Cttl/Cprotocol/nchecksum/Nsource/Ndestination",$ippacket);
		$this->version = $buffer['version_ihl'] >> 4;
		$this->ihl     = $buffer['version_ihl'] & 0xf;
		unset($buffer['version_ihl']);
//		$this->tos = $x['flags_offset'] >> 13;
//$x['offset'] = $x['flags_offset'] & 0x1fff;
		$this->length  = $buffer['length'];
		$this->proto   = $buffer['protocol'];
		$this->srcip   = long2ip($buffer['source']);
		$this->dstip   = long2ip($buffer['destination']);
		unset($buffer);
		$payloadOffset = (($this->ihl * 32)/8);
//		echo "iphdrlen:".$payloadOffset."<br />\n";
		//$this->payload = mb_substr($ippacket,$payloadOffset);
		$this->payload = substr($ippacket,$payloadOffset);
	}

	// basic parsing
	public function protoToString()
	{
		switch ($this->proto)
		{
			case 1:
				return "ICMP";
				break;
			
			case 2:
				return "IGMP";
				break;
				
			case 6:
				return "TCP";
				break;
			
			case 8:
				return "EGP";
				break;
				
			case 9:
				return "IGP";
				break;
		
			case 17:
				return "UDP";
				break;
				
			case "50":
				return "ESP";
				break;
				
			case "51":
				return "AH";
				break;
				
			default;
				return "UNKNOWN";
		}
	}
}

class udp_header
{
	public $sourcePort;
	public $destinationPort;
	public $length;
	public $checksum;
//	public $payload;

	function __construct($udpsegment)
	{
		$this->sourcePort      = "";
		$this->destinationPort = "";
		$this->length          = "";
		$buffer = unpack("nsource_port/ndestination_port/nlength/nchecksum",$udpsegment);
		
		$this->sourcePort      = $buffer['source_port'];
		$this->destinationPort = $buffer['destination_port'];
		$this->length          = $buffer['length'];
		$this->checksum        = $buffer['checksum'];
		unset($buffer);
	}
}

class tcp_header
{
	public $sourcePort;
	public $destinationPort;
	public $sequenceNumber;
	public $acknowledgment;
	public $length;
	public $flags;
	public $window;
	public $checksum;
//	public $payload;

	function __construct($tcpsegment)
	{
		$this->sourcePort      = "";
		$this->destinationPort = "";
		$this->sequenceNumber  = "";
		$this->length          = "";
		$this->flags           = "";
		$this->length          = "";
		$this->window          = "";
		$this->checksum        = "";
		$buffer = unpack("nsource_port/ndestination_port/nseqnum1/nseqnum2/nacknum1/nacknum2/nmisc/nwindow/nchecksum",$tcpsegment);
		$this->sourcePort      = $buffer['source_port'];
		$this->destinationPort = $buffer['destination_port'];
		$this->sequenceNumber  = $buffer['seqnum1'].$buffer['seqnum2'];	// not sequence and acknowledge number must be saved as string, as PHP cannot handle unsigned 32bit numbers
		$this->acknowledgment  = $buffer['acknum1'].$buffer['acknum2'];
		$this->length          = $buffer['misc'];
		$this->flags           = $buffer['misc'] & 0x3f; // 6 bit
		$this->window          = $buffer['window'];
		$this->checksum        = $buffer['checksum'];
		unset($buffer);
		// $udpsegment is an array
//		if (sizeOf($tcpsegment)>3)
//		{
//			$this->sourcePort      = $tcpsegment[1];
//			$this->destinationPort = $tcpsegment[2];
//			$this->sequenceNumber  = $tcpsegment[3].$tcpsegment[4];
//			$this->acknowledgment  = $tcpsegment[5].$tcpsegment[6];
			
//			$this->length          = $tcpsegment[3];
//		}
//$x = unpack("nsource_port/ndestination_port/nlength/nchecksum",$data);
//$x['data'] = substr($data,8,$x['length']-8);
		
//$x['data'] = substr($data,$x['ihl']*4,$x['length']-$x['ihl']*4); // ignoring options
//return $x;
	}
	
	
}

// create pseudo header from a packet, assembles wireshark like informations, useful in Packet List View
class pseudo_header
{
	public $tsSec;         /* timestamp seconds */
	public $tsUsec;        /* timestamp microseconds */
	public $frameLength;   // frame Length
	public $protocol;
	public $dataLinkSource;
	public $dataLinkDestination;
	public $sourceAddress;	    // it can be datalink or network sources address
	public $destinationAddress;	// it can be datalink or network sources address
	public $sourcePort;
	public $destinationPort;
	public $tcpdata;
	public $tcpdatalen;
	public $udpdata;
	public $udpdatalen;
	public $flags;
	public $info;	// summary of packet

	function __construct($packetHeader,$ethernetHeader=null)
	{
		$this->tsSec               = $packetHeader->ts_sec;
		$this->tsUsec              = $packetHeader->ts_usec;
		$this->frameLength         = $packetHeader->orig_len;
		$this->dataLinkSource      = $ethernetHeader->srcmac;
		$this->dataLinkDestination = $ethernetHeader->dstmac;
		$this->protocol            = $ethernetHeader->typeToString();
		$this->sourceAddress       = $this->dataLinkSource ;	    // it can be datalink or network sources address
		$this->destinationAddress  = $this->dataLinkDestination;	// it can be datalink or network sources address
		$this->sourcePort          = "";
		$this->destinationPort     = "";
		$this->tcpdata             = "";
		$this->tcpdatalen          = "";
		$this->udpdata             = "";
		$this->udpdatalen          = "";
		$this->flags               = "";
		$this->info                = "";
		// detect protocol as a string
		$type = $ethernetHeader->typeToString();
		// see what we figure out about this packet
		switch ($type)
		{
			case "ARP":
				$arp                       = new arp_header($ethernetHeader->payload);	// pass ethernet payload
				$this->protocol           = "ARP";
				// Request
				if ($arp->opcode==1) { $this->info = "Who has ".$arp->dstip."? Tell ".$arp->srcip; }
				// Reply
				if ($arp->opcode==2) { $this->info = $arp->srcip." is at ".$arp->srcmac; }				
				break;

			case "IPv4":
				$ip                       = new ipv4_header($ethernetHeader->payload);	// pass ethernet payload
				$this->sourceAddress      = $ip->srcip;
				$this->destinationAddress = $ip->dstip;
				switch ($ip->protoToString())
				{
					case "UDP":
						$udp = new udp_header($ip->payload);	// pass ip payload
						$this->sourcePort      = $udp->sourcePort;
						$this->destinationPort = $udp->destinationPort;
						$this->udpdatalen      = $udp->length;
						$this->info    = "Source Port: ".$this->sourcePort." Destination Port: ".$this->destinationPort;
						break;
					case "TCP":
						$tcp = new tcp_header($ip->payload);	// pass ip payload
						$this->sourcePort      = $tcp->sourcePort;
						$this->destinationPort = $tcp->destinationPort;
						// Flags (6-bit only)
						$tmpFlg = array();
						if (($tcp->flags & 1)==1) { $tmpFlg[] = "FIN"; }
						if (($tcp->flags & 2)==2) { $tmpFlg[] = "SYN"; }
						if (($tcp->flags & 4)==4) { $tmpFlg[] = "RST"; }
						if (($tcp->flags & 8)==8) { $tmpFlg[] = "PSH"; }
						if (($tcp->flags & 16)==16) { $tmpFlg[] = "ACK"; }
						if (($tcp->flags & 32)==32) { $tmpFlg[] = "URG"; }
						foreach ($tmpFlg as $flag)
						{
							$myFlag .= $flag.", ";
						}
						$myFlag = substr($myFlag,0,strlen($myFlag)-2);
						// depending on tcp state
						$this->info    = $this->sourcePort." > ".$this->destinationPort." [".$myFlag."] Seq=".$tcp->sequenceNumber." Ack=".$tcp->acknowledgment;
//						$this->info    = $this->sourcePort." > ".$this->destinationPort." [FLG/".$tcp->flags."/".$myFlag."] Seq=".$tcp->sequenceNumber." Ack=".$tcp->acknowledgment;
						break;
				}
				$this->protocol = $ip->protoToString();

				// resolver
//				if (CONFIG_VIEW_RESOLVE)
	//			{
//					$this->sourceAddress      = gethostbyaddr($this->sourceAddress);
//					$this->destinationAddress = gethostbyaddr($this->destinationAddress);
//				}
				$ip                       = null;
				break;
			
			case "IPv6":
				$this->protocol           = $ethernetHeader->typeToString();
				//$this->sourceAddress      = $ethernetHeader->srcmac;
				//$this->destinationAddress = $ethernetHeader->dstmac;
				break;

			case "ICMP":
				$ip                       = new ipv4_header($ethernetHeader->payload);
				$this->protocol           = $ip->protoToString();
				$this->sourceAddress      = $ip->srcip;
				$this->destinationAddress = $ip->dstip;
				$ip                       = null;

			case "UNKNOWN":
				break;
			
//				$buffer = unpack("Vts_sec/Vts_usec/Vincl_len/Vorig_len",fread($fh,16));	
				break;

			default:
				$this->protocol           = $ethernetHeader->typeToString();
				break;
		
		}
		
	}
}
?>
