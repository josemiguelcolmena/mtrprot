_G.debug = require("debug")

-- create myproto protocol and its fields
p_myproto = Proto ("mtrPROT","Meterpreter protocol")
local f_command = ProtoField.uint32("mtrPROT.command", "Length", base.HEX)
local f_type = ProtoField.uint32("mtrPROT.type", "Type", base.HEX)
local f_data = ProtoField.bytes("mtrPROT.data", "Data", FT_STRING)
local f_data_string = ProtoField.string("mtrPROT.data_string", "String", FT_STRING)
local command_length
local meterpreter_command
local command_type
local command_type_string
local test = 0
local tipos_nombre = {}
local tipos_tipo = {}
local TLV_META_TYPE_NONE = 0
local TLV_META_TYPE_STRING 
local TLV_META_TYPE_UINT
local TLV_META_TYPE_RAW
local TLV_META_TYPE_BOOL
local TLV_META_TYPE_QWORD
local TLV_META_TYPE_COMPRESSED 
local TLV_META_TYPE_GROUP 
local TLV_META_TYPE_COMPLEX 
local TLV_RESERVED = 0
local TLV_EXTENSIONS = 20000
local TLV_USER = 40000
local TLV_TEMP = 60000
local tipos_len
p_myproto.fields = {f_command, f_type, f_data}
 
function addtipo (index,nombre, valor)
	tipos_nombre[index] = nombre
	tipos_tipo[index] = valor
end

function initdata()
	TLV_META_TYPE_STRING = bits(bit.lshift(1,16))
	TLV_META_TYPE_UINT = bits(bit.lshift(1,17))
	TLV_META_TYPE_RAW = bits(bit.lshift(1,18))
	TLV_META_TYPE_BOOL = bits(bit.lshift(1,19))
	TLV_META_TYPE_QWORD = bits(bit.lshift(1,20))
	TLV_META_TYPE_COMPRESSED = bits(bit.lshift(1,29))
	TLV_META_TYPE_GROUP = bits(bit.lshift(1,30))
	TLV_META_TYPE_COMPLEX = bits(bit.lshift(1,31))
	
	addtipo(0,"TLV_META_TYPE_NONE",0)
	addtipo(1,"TLV_META_TYPE_STRING",bits(bit.lshift(1,16)))
	addtipo(2,"TLV_META_TYPE_UINT",bits(bit.lshift(1,17)))
	addtipo(3,"TLV_META_TYPE_RAW",bits(bit.lshift(1,18)))
	addtipo(4,"TLV_META_TYPE_BOOL",bits(bit.lshift(1,19)))
	addtipo(5,"TLV_META_TYPE_QWORD",bits(bit.lshift(1,20)))
	addtipo(6,"TLV_META_TYPE_COMPRESSED",bits(bit.lshift(1,29)))
	addtipo(7,"TLV_META_TYPE_GROUP",bits(bit.lshift(1,30)))
	addtipo(8,"TLV_META_TYPE_COMPLEX",bits(bit.lshift(1,31)))

	addtipo(9,"TLV_TYPE_ANY", bits(0))
	addtipo(10,"TLV_TYPE_METHOD",bits(65536+1))
	addtipo(11,"TLV_TYPE_REQUEST_ID",bits(65536+2))
	addtipo(12,"TLV_TYPE_EXCEPTION",bits(1073741824+3))
	addtipo(13,"TLV_TYPE_RESULT",bits(131072+4))

	addtipo(14,"TLV_TYPE_STRING",bits(65536+10))
	addtipo(15,"TLV_TYPE_UINT",bits(131072+11))
	addtipo(16,"TLV_TYPE_BOOL",bits(524288+12))

	addtipo(17,"TLV_TYPE_LENGTH",bits(131072+25))
	addtipo(18,"TLV_TYPE_DATA",bits(262144+26))
	addtipo(19,"TLV_TYPE_FLAGS",bits(131072+27))

	addtipo(20,"TLV_TYPE_CHANNEL_ID",bits(131072+50))
	addtipo(21,"TLV_TYPE_CHANNEL_TYPE",bits(65536+51))
	addtipo(22,"TLV_TYPE_CHANNEL_DATA",bits(262144+52))
	addtipo(23,"TLV_TYPE_CHANNEL_DATA_GROUP",bits(1073741824+53))
	addtipo(24,"TLV_TYPE_CHANNEL_CLASS",bits(131072+54))

	addtipo(25,"TLV_TYPE_SEEK_WHENCE",bits(131072+70))
	addtipo(26,"TLV_TYPE_SEEK_OFFSET",bits(131072+71))
	addtipo(27,"TLV_TYPE_SEEK_POS",bits(131072+72))

	addtipo(28,"TLV_TYPE_EXCEPTION_CODE",bits(131072+300))
	addtipo(29,"TLV_TYPE_EXCEPTION_STRING",bits(65536+301))

	addtipo(30,"TLV_TYPE_LIBRARY_PATH",bits(65536+400))
	addtipo(31,"TLV_TYPE_TARGET_PATH",bits(65536+401))
	addtipo(32,"TLV_TYPE_MIGRATE_PID",bits(131072+402))
	addtipo(33,"TLV_TYPE_MIGRATE_LEN",bits(131072+403))

	addtipo(34,"TLV_TYPE_MACHINE_ID",bits(65536+460))
	addtipo(35,"TLV_TYPE_UUID",bits(262144+461))

	addtipo(36,"TLV_TYPE_CIPHER_NAME",bits(65536+500))
	addtipo(37,"TLV_TYPE_CIPHER_PARAMETERS",bits(262144+501))
	
	addtipo(38,"TLV_TYPE_HANDLE",bits(1048576 + 600))
	addtipo(39,"TLV_TYPE_INHERIT",bits(524288 + 601))
	addtipo(40,"TLV_TYPE_PROCESS_HANDLE",bits(1048576 + 630))
	addtipo(41,"TLV_TYPE_THREAD_HANDLE",bits(1048576 + 631))

	addtipo(42,"TLV_TYPE_DIRECTORY_PATH", bits(65536  + 1200))
	addtipo(43,"TLV_TYPE_FILE_NAME", bits(65536  + 1201))
	addtipo(44,"TLV_TYPE_FILE_PATH", bits(65536  + 1202))
	addtipo(45,"TLV_TYPE_FILE_MODE", bits(65536  + 1203))
	addtipo(46,"TLV_TYPE_FILE_SIZE", bits(131072 + 1204))
	addtipo(47,"TLV_TYPE_FILE_HASH", bits(262144 + 1206))

	addtipo(48,"TLV_TYPE_STAT_BUF", bits(2147483648 + 1220))
	
	addtipo(49,"TLV_TYPE_SEARCH_RECURSE", bits(524288 + 1230))
	addtipo(50,"TLV_TYPE_SEARCH_GLOB", bits(65536 + 1231))
	addtipo(51,"TLV_TYPE_SEARCH_ROOT", bits(65536 + 1232))
	addtipo(52,"TLV_TYPE_SEARCH_RESULTS", bits(1073741824 + 1233))

	addtipo(53,"TLV_TYPE_HOST_NAME", bits(65536 + 1400))
	addtipo(54,"TLV_TYPE_PORT", bits(131072 + 1401))

	addtipo(55,"TLV_TYPE_SUBNET", bits(262144 + 1420))
	addtipo(56,"TLV_TYPE_NETMASK", bits(262144 + 1421))
	addtipo(57,"TLV_TYPE_GATEWAY", bits(262144 + 1422))
	addtipo(58,"TLV_TYPE_NETWORK_ROUTE", bits(1073741824 + 1423))

	addtipo(59,"TLV_TYPE_IP", bits(262144 + 1430))
	addtipo(60,"TLV_TYPE_MAC_ADDRESS", bits(262144 + 1431))
	addtipo(61,"TLV_TYPE_MAC_NAME", bits(65536 + 1432))
	addtipo(62,"TLV_TYPE_NETWORK_INTERFACE", bits(1073741824 + 1433))

	addtipo(63,"TLV_TYPE_SUBNET_STRING", bits(65536 + 1440))
	addtipo(64,"TLV_TYPE_NETMASK_STRING", bits(65536 + 1441))
	addtipo(65,"TLV_TYPE_GATEWAY_STRING", bits(65536 + 1442))

	addtipo(66,"TLV_TYPE_PEER_HOST", bits(65536 + 1500))
	addtipo(67,"TLV_TYPE_PEER_PORT", bits(131072 + 1501))
	addtipo(68,"TLV_TYPE_LOCAL_HOST", bits(65536 + 1502))
	addtipo(69,"TLV_TYPE_LOCAL_PORT", bits(131072 + 1503))
	addtipo(70,"TLV_TYPE_CONNECT_RETRIES", bits(131072 + 1504))

	addtipo(71,"TLV_TYPE_SHUTDOWN_HOW", bits(131072 + 1530))

	--addtipo( ,"TLV_TYPE_HKEY", bits(1048576 + 1000))
	addtipo(72,"TLV_TYPE_ROOT_KEY", bits(           1048576 + 1000))
	addtipo(73,"TLV_TYPE_BASE_KEY", bits(65536 + 1001))
	addtipo(74,"TLV_TYPE_PERMISSION", bits(131072 + 1002))
	addtipo(75,"TLV_TYPE_KEY_NAME", bits(65536 + 1003))
	addtipo(76,"TLV_TYPE_VALUE_NAME", bits(65536 + 1010))
	addtipo(77,"TLV_TYPE_VALUE_TYPE", bits(131072 + 1011))
	addtipo(78,"TLV_TYPE_VALUE_DATA", bits(262144 + 1012))

	addtipo(79,"TLV_TYPE_COMPUTER_NAME", bits(65536 + 1040))
	addtipo(80,"TLV_TYPE_OS_NAME", bits(     65536 + 1041))
	addtipo(81,"TLV_TYPE_USER_NAME", bits(   65536 + 1042))
	addtipo(82,"TLV_TYPE_ARCHITECTURE", bits(65536 + 1043))
	addtipo(83,"TLV_TYPE_LANG_SYSTEM", bits( 65536 + 1044))

	addtipo(84,"TLV_TYPE_ENV_VARIABLE", bits(65536 + 1100))
	

	addtipo(85,"TLV_TYPE_BASE_ADDRESS", bits(       1048576 + 2000))
	addtipo(86,"TLV_TYPE_ALLOCATION_TYPE", bits(     131072 + 2001))
	addtipo(87,"TLV_TYPE_PROTECTION", bits(          131072 + 2002))
	addtipo(88,"TLV_TYPE_PROCESS_PERMS", bits(       131072 + 2003))
	addtipo(89,"TLV_TYPE_PROCESS_MEMORY", bits(     262144 + 2004))
	addtipo(90,"TLV_TYPE_ALLOC_BASE_ADDRESS", bits( 1048576 + 2005))
	addtipo(91,"TLV_TYPE_MEMORY_STATE", bits(        131072 + 2006))
	addtipo(92,"TLV_TYPE_MEMORY_TYPE", bits(         131072 + 2007))
	addtipo(93,"TLV_TYPE_ALLOC_PROTECTION", bits(    131072 + 2008))
	addtipo(94,"TLV_TYPE_PID", bits(                 131072 + 2300))
	addtipo(95,"TLV_TYPE_PROCESS_NAME", bits(65536 + 2301))
	addtipo(96,"TLV_TYPE_PROCESS_PATH", bits(65536 + 2302))
	addtipo(97,"TLV_TYPE_PROCESS_GROUP", bits(      1073741824 + 2303))
	addtipo(98,"TLV_TYPE_PROCESS_FLAGS", bits(       131072 + 2304))
	addtipo(99,"TLV_TYPE_PROCESS_ARGUMENTS", bits(  65536 + 2305))

	addtipo(100,"TLV_TYPE_IMAGE_FILE", bits(  65536 + 2400))
	addtipo(101,"TLV_TYPE_IMAGE_FILE_PATH", bits(    65536 + 2401))
	addtipo(102,"TLV_TYPE_PROCEDURE_NAME", bits(     65536 + 2402))
	addtipo(103,"TLV_TYPE_PROCEDURE_ADDRESS", bits(  1048576 + 2403))
	addtipo(104,"TLV_TYPE_IMAGE_BASE", bits(         1048576 + 2404))
	addtipo(105,"TLV_TYPE_IMAGE_GROUP", bits(        1073741824 + 2405))
	addtipo(106,"TLV_TYPE_IMAGE_NAME", bits(  65536 + 2406))

	addtipo(107,"TLV_TYPE_THREAD_ID", bits(           131072 + 2500))
	addtipo(108,"TLV_TYPE_THREAD_PERMS", bits(        131072 + 2502))
	addtipo(109,"TLV_TYPE_EXIT_CODE", bits(           131072 + 2510))
	addtipo(110,"TLV_TYPE_ENTRY_POINT", bits(        1048576 + 2511))
	addtipo(111,"TLV_TYPE_ENTRY_PARAMETER", bits(    1048576 + 2512))
	addtipo(112,"TLV_TYPE_CREATION_FLAGS", bits(      131072 + 2513))

	addtipo(113,"TLV_TYPE_REGISTER_NAME", bits(65536 + 2540))
	addtipo(114,"TLV_TYPE_REGISTER_SIZE", bits(       131072 + 2541))
	addtipo(115,"TLV_TYPE_REGISTER_VALUE_32", bits(   131072 + 2542))
	addtipo(116,"TLV_TYPE_REGISTER", bits(           1073741824 + 2550))

	addtipo(117,"TLV_TYPE_IDLE_TIME", bits(           131072 + 3000))
	addtipo(118,"TLV_TYPE_KEYS_DUMP", bits(          65536 + 3001))
	addtipo(119,"TLV_TYPE_DESKTOP", bits(            65536 + 3002))

	addtipo(120,"TLV_TYPE_EVENT_SOURCENAME", bits(   65536 + 4000))
	addtipo(121,"TLV_TYPE_EVENT_HANDLE", bits(       1048576 + 4001))
	addtipo(122,"TLV_TYPE_EVENT_NUMRECORDS", bits(    131072 + 4002))

	addtipo(123,"TLV_TYPE_EVENT_READFLAGS", bits(     131072 + 4003))
	addtipo(124,"TLV_TYPE_EVENT_RECORDOFFSET", bits(  131072 + 4004))

	addtipo(125,"TLV_TYPE_EVENT_RECORDNUMBER", bits(  131072 + 4006))
	addtipo(126,"TLV_TYPE_EVENT_TIMEGENERATED", bits( 131072 + 4007))
	addtipo(127,"TLV_TYPE_EVENT_TIMEWRITTEN", bits(   131072 + 4008))
	addtipo(128,"TLV_TYPE_EVENT_ID", bits(            131072 + 4009))
	addtipo(129,"TLV_TYPE_EVENT_TYPE", bits(          131072 + 4010))
	addtipo(130,"TLV_TYPE_EVENT_CATEGORY", bits(      131072 + 4011))
	addtipo(131,"TLV_TYPE_EVENT_STRING", bits(       65536 + 4012))
	addtipo(132,"TLV_TYPE_EVENT_DATA", bits(          262144 + 4013))

	addtipo(133,"TLV_TYPE_ENV_VALUE", bits(   65536 + 1101))
	addtipo(134,"TLV_TYPE_ENV_GROUP", bits(1073741824 + 1102))
	tipos_len = 135
end
 
 function find_tipo(valor)
	--warn("bits: "..bits(1))
	for i=0,tipos_len-1,1 do
		local tipo = tipos_tipo[i]
		--warn("valor: "..bits(valor).." tipo: "..tipo.." tipos_nombre: "..tipos_nombre[i])
		if bits(valor) == tipo then
			return tipos_nombre[i]
		end
	end
	return valor
 end 
 
 function bits(num)
    local t={}
    while num>0 do
        rest=num%2
        table.insert(t,1,rest)
        num=(num-rest)/2
    end return table.concat(t)
end

function getcommand(buf)
  local i=0
  local buflen = buf:len()
  local command = ""
  --warn(i)
  --warn(buflen)
  while ( i<buflen) do
    local val = tonumber("0x"..tostring(buf(i,1)))
    --warn("leido: "..tostring(buf(i,1)))
    --warn("val: "..val)
    --warn("i: "..i)
    if val == 0 then
      --warn(buf(0,i))
      --warn("i: "..i)
      return i
      --return tostring(buf(0,i-1))
    end
    i = i+1
  end
  return buflen
end

function bytestostring(bytes)
  s = ""
  buflen = bytes:len()
  warn(bytes)
  for i = 0, buflen-1 do;
    val = tonumber("0x"..tostring(bytes(i,1)))
    --warn(val)
    if val ~= 0 then
      s = s .. string.char(val) 
    end
  end
  return s
end

function extract_tlv(buf, root, test)
	
	local subtree = root:add(p_myproto, buf(0))
	local length = tonumber("0x"..tostring(buf(0,4)))
	if (length>buf:len()) then
		length = buf:len()
	end
	--test = test+1
	--warn("test: "..test.." length: "..length)
	--if test >2 then 
		
	--	return 0
	--end
	local tipo = tonumber("0x"..tostring(buf(4,4)))
	warn("length: ".. tonumber("0x"..tostring(buf(0,4))))
	warn("type: ".. tipo)
	warn("buf len: "..buf:len())
	
	subtree:append_text(", TLV details")
	if (tipo == 1073744127) then
		meterpreter_command = length -8
	else
		meterpreter_command = getcommand(buf(8,buf:len()-8))
	end
	meterpreter_command = length -8
	--meterpreter_command = getcommand(buf(8,buf:len()-8))
    warn(meterpreter_command)
    --subtree:add(f_data_string, meterpreter_command):append_text(" [Meterpreter command] ")
     
	subtree:add(f_data, buf(0,length-1)):append_text(" [TLV]")  
	subtree:add(f_command, buf(0,4)):append_text(" [Length]: "..length)
	local nombre = find_tipo(tipo)
	subtree:add(f_type, buf(4,4)):append_text(" [Type: ".. command_type_string .."]: "..nombre)
	
	warn("nombre: "..nombre.." tipo: "..tipo)
	local comando = bytestostring(buf(8,meterpreter_command))

	--if (comando:len()==0 and length == 12) then
	if (length == 12) then
		warn(" test: "..tostring(buf(8,length-8)))
		local valor = tonumber("0x"..tostring(buf(8,length-8)))
		--comando = "Finish"
		if (valor==0) then 
			comando = "OK"
		else
			if (valor==1) then 
				comando = "ERROR"
			else
				warn(valor)
				comando = ""..valor
			end
		end
		
		meterpreter_command = 4
	end
	subtree:add(f_data, buf(8,meterpreter_command)):append_text(" [Value] "..comando)
	
	--subtree:add(f_data, buf(8,buf:len()-8)):append_text(" [TLV payload]")
	warn("meterpreter_command: "..meterpreter_command)
	warn("buf:len: "..buf:len())
	
	--if meterpreter_command < (buf:len()) then
	if buf:len()-length >0 then
		local offset = 0;
		offset = (length - meterpreter_command-8)
		warn(buf:len()-length)
		extract_tlv(buf(length, buf:len()-length),root, test)
	end
end

-- myproto dissector function
function p_myproto.dissector (buf, pkt, root)
	local test = 0
  command_length = tonumber("0x"..tostring(buf(0,4)))
  command_type = tonumber(tostring(buf(4,4)))
  warn("command length: ".. tonumber("0x"..tostring(buf(0,4))))
  warn("command type: ".. tonumber(tostring(buf(4,4))))
  -- validate packet length is adequate, otherwise quit
  if buf:len() == 0 then return end
  pkt.cols.protocol = p_myproto.name
 
  -- create subtree for myproto
  subtree = root:add(p_myproto, buf(0))
  -- add protocol fields to subtree
  --local payloadstring = bytestostring(buf(0,4))
  subtree:add(f_command, buf(0,4)):append_text(" [Command length]: "..command_length)
  if buf:len()>4 then
    if command_type == 0 then command_type_string = "Request" end
    if command_type == 1 then command_type_string = "Response" end
    if command_type == 10 then command_type_string = "Plain Request" end
    if command_type == 11 then command_type_string = "Plain Response" end

    subtree:add(f_type, buf(4,4)):append_text(" [Command type: ".. command_type_string .."]: "..command_type)
    if command_type == 0 or command_type == 1 then
		
		subtree:add(f_data, buf(8,buf:len()-8)):append_text(" [Command payload]")
		extract_tlv(buf(8,buf:len()-8), root, test)
		
    end
    
  end
  -- description of payload
  subtree:append_text(", Command details here or in the tree below")
end
 
-- Initialization routine
function p_myproto.init()
	initdata()
end
 
-- register a chained dissector for port 4444
local tcp_dissector_table = DissectorTable.get("tcp.port")
dissector = tcp_dissector_table:get_dissector(4444)
  -- you can call dissector from function p_myproto.dissector above
  -- so that the previous dissector gets called
tcp_dissector_table:add(4444, p_myproto)
