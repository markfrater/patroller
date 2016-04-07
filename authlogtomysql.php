#!/usr/bin/php
<?php
/****************************************************************************
*                                                                           *
*    This script takes authentication data from Mikrotik syslog devices     *
*    and inserts into the Patroller database.                               *
*    Copyright 2014                                                         *
*    Last Update = 5 Apr 2016                                               *
*    By: Mark Frater                                                        *
*    Change = add login /logout of Devices to RouterDevice                  *
*                                                                           *
****************************************************************************/
// known bugs: If oui not found, entry will not get added to RouterDevice


if (isset($_SERVER['REQUEST_URI'])) return;
define("STARTED_FROM_INDEX", 2);
chdir(dirname($argv[0]));
if(!include("authconfig_constants.php")) {
    echo date("Y-m-d H:i | ") . "No configuration written!\n";
} else {
    include('DB.php');
    while( true ) {
            $pid = pcntl_fork();
            if ($pid == -1) {
            die('could not fork');
        } else if ($pid) {
            pcntl_waitpid($pid, $status); //Protect against Zombie children
            sleep(1);
            continue;
        } else {
            set_time_limit(0);
            ob_implicit_flush();
            define("DEBUG", 0);
            define("IP_DIGIT", "(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)");
            define("IP_REGEXP", "^" . IP_DIGIT . "\\." . IP_DIGIT . "\\." . IP_DIGIT . "\\." . IP_DIGIT . "$");
            $MYSQL_PIPE = "/home/proxylizer/mysqlauth.pipe";
            // tell PEAR to write no backtrace
            $skiptrace = &PEAR::getStaticProperty('PEAR_Error', 'skiptrace');
            $skiptrace = true;

            /////////////////////////////////////

            //print_r($_SERVER);
            while (true) {
                $file = @fopen($MYSQL_PIPE, "r");
                if ($file == false) {
                echo date("Y-m-d H:i | ") . "Error : Can't open file {$MYSQL_PIPE}\n";
                sleep(1);
                continue;
                }
                if ($db = connectDB()) {
                    while ($line = fgets($file)) {
                        $line = str_replace("\n", "", $line);
                        echo "{$line}\n";
                        $rawlog = explode(": ", $line); // split line by colon followed by space.

// typical new client line
// 117.104.178.217 21-07-2014 23:46:43 seaview2 hotspot-remote-user: 3C:D0:F8:79:A7:A5 (192.168.123.250): trying to log in by mac
// 117.104.178.217 21-07-2014  23:46:43 seaview2 hotspot-remote-user: 3C:D0:F8:79:A7:A5 (192.168.123.250): login failed: invalid username or password

// wired device logging in by mac
//117.104.176.215 21-09-2014 22:48:31 seaview2 hotspot-remote-user: 70:58:12:0C:49:27 (192.168.88.251): trying to log in by mac-cookie
//117.104.176.215 21-09-2014 22:48:31 seaview2 hotspot-remote-user: 70:58:12:0C:49:27 (192.168.88.251): logged in

// typical username password login
// 117.104.178.217 03-07-2104 22:23:16 seaview2 hotspot-remote-user: 70:58:12:0C:49:27 (192.168.88.251): logged in
// 117.104.178.217 03-07-2014 19:04:42 seaview2 hotspot-remote-user: sylvie (192.168.123.246): logged in

//typical username password logout
// 117.104.178.217 21-07-2014 20:14:19 seaview2 hotspot-remote-user: sylvie (192.168.123.246): logged out: keepalive timeout

//typical failed login
// 117.104.178.217 21-07-2014 19:04:13 seaview2 hotspot-remote-user: 20:16:D8:51:E2:3A (192.168.123.250): login failed: invalid username or password

// unknown device
//117.104.177.207 19-08-2014 23:13:44 seaview2 hotspot-remote-user: 3C:D0:F8:79:A7:A5 (192.168.123.249): trying to log in by mac
//117.104.177.207 19-08-2014 23:13:44 seaview2 hotspot-remote-user: 3C:D0:F8:79:A7:A5 (192.168.123.249): login failed: invalid username or password


                        $source = explode(" ",$rawlog['0']);
                        $userinfo = explode(" ",$rawlog['1']);
                        $result = $rawlog['2'];
                        if (array_key_exists(3,$rawlog)) {
                                $message = $rawlog['3'];
                        } else {
                                $message = "";
                        }
                        echo "rawlog0 = ".$rawlog['0']."\n";
                        echo "rawlog1 = ".$rawlog['1']."\n";
                        echo "rawlog2 = ".$rawlog['2']."\n";

                        echo "userinfo0 = ".$userinfo['0']."\n";
                        echo "result = $result\n";
                        echo "message = $message\n";

                        $sourceIP = $source['0'];
                        $sourceIP = preg_replace("/[^0-9\.]/", "" ,$sourceIP);
                        $sourceIP = eregIP($sourceIP);
                        $date = $source['1'];
                        $time = $source['2'];
                        echo "time = $time\n";
                        echo "date = $date\n";
                        $hostname = filter_var($source['3'], FILTER_SANITIZE_STRING);
                        $username = filter_var($userinfo['0'], FILTER_SANITIZE_STRING);
//                      $mac = preg_replace("/^([0-9A-F]{2}[:-]){5}([0-9A-F]{2})$/", "",$mac);
                        $enddeviceIP = $userinfo['1'];
                echo "enddeviceIP before ereg = $enddeviceIP\n";
                        $enddeviceIP = preg_replace("/[^0-9\.]/", "" ,$enddeviceIP);
//                      $enddeviceIP = eregIP($enddeviceIP);
                echo "enddeviceIP after ereg = $enddeviceIP\n";
                        $date = strtotime($date);
                        $date = date("Y-m-d",$date);
                        $time = strtotime($time);
                        $time = date("H:i:s",$time);
                        $date = $date." ".$time;
                        echo "DateTime = $date\n";
//                      echo "Hostname = $hostname \n";
                        if ($sourceIP !== false) {
                            if(insertLine($db));
                            if(updateUser($db));
                            if (substr($result,0,23)=="trying to log in by mac"){ // subtring now catches login by mac and mac-cookie
                                if(insertDevice($db));                            // this now updates status, lastIp and lastSeen if RouterDevice.macAddress already exists.
                                // if that RouterDevice is assigned to a User, then we need to get the RouterDevice.userId and update the User.status to $result as well.
                                // UPDATE User, Router RouterDevice set User.lastLog='{$date}',User.status= '{$result}'
                                // WHERE User.customerId = Router.customerId
                                // AND Router.hostName='{$hostname}'
                                // AND User.id = (select RouterDevice.userId from RouterDevice where RouterDevice.macAddress='{$username}'";

                            }
                        } else {
                            echo date("Y-m-d H:i | ") . "Invalid IP address!!!\n";
                        }
                    }
                $db->disconnect();
                }
                fclose($file);
            }
        }
    }
}

function eregIP ($ip) {
    if (ereg(IP_REGEXP, $ip)) {
        return $ip;
    } else {
        return false;
    }
}

function connectDB() {
    global $config_const;
    $DBpaswrd = $config_const['DB_PASSWORD'];
    if ($DBpaswrd != "") $DBpaswrd = ":" . $DBpaswrd;
    $dsn = "{$config_const['DB_TYPE']}://{$config_const['DB_USERNAME']}{$DBpaswrd}@{$config_const['DB_HOST']}/{$config_const['DB_NAME']}";
    $options = array(
    'debug'       => 2,
    'portability' => DB_PORTABILITY_ALL,
    );
    do {
        $db = & DB::connect($dsn, $options);
        if (PEAR::isError($db)) {
            echo "/1/ ";
            echo date("Y-m-d H:i | ") . "Code " . $errcode=$db->getcode() . " ";
            echo $db->getMessage() . "\n";
            if ($errcode == DB_ERROR_ACCESS_VIOLATION || $errcode == DB_ERROR_NOSUCHDB) {
                return false;
            }
            return false;
        } else {
            return $db;
        }
    } while (true);
}

//
// Insert a log entry into the Authlog table.
//

function insertLine (& $db) {
    global $sourceIP, $date, $time, $hostname, $username, $enddeviceIP, $result, $message ;
    $query = "INSERT INTO authlog (sourceIP,date,hostname,username,enddeviceIP,result,message)
                    VALUES ('{$sourceIP}','{$date}','{$hostname}','{$username}','{$enddeviceIP}','{$result}','{$message}')";
        do {
            $insertdata = & $db->query($query);
            $iserror = false;
            if (PEAR::isError($insertdata)) {
                $msg = $insertdata->getMessage() . "\n";
                $errcode = $insertdata->getCode();
                if ($errcode == DB_ERROR_ACCESS_VIOLATION || $errcode == DB_ERROR_NOSUCHDB ||
                            $errcode == DB_ERROR_NODBSELECTED || $errcode == DB_ERROR ||
                            $errcode == DB_ERROR_NODBSELECTED) {
                    // no connection, etc
                    echo "/3/ ";
                    echo date("Y-m-d H:i | ") . "CODE: " . $insertdata->getCode() . " ";
                    echo $insertdata->getMessage() . " \n";
                    $iserror = false;
                    //$db->disconnect();
                    $db = connectDB();
                } else {
                    echo "/4/ ";
                    echo date("Y-m-d H:i | ") . $insertdata->getMessage() . "\n";
                    echo $query. "\n";
                }
            }
        } while ($iserror ==true);
    }

function updateUser (& $db) {
    global $sourceIP, $date, $time, $hostname, $username, $enddeviceIP, $result, $message ;

//mysql> UPDATE User, Router set User.status = 'hellotest'
//       WHERE User.customerId = Router.customerId AND
//       Router.hostName='Seaview2' AND
//       User.weblogin='mfrater';
//Query OK, 1 row affected (0.06 sec)

// Would like to enhance this to see if the device (or user)? already exists.
// If not, then should add the device as "unallocated" to the Users Account.
//
// So, first work out if the $username is listed as a User.weblogin of the account with a router = $hostname (ie routername).
// If the $username is not found, then its probably a login is from a RouterDevice that logs in via MAC, that is associated
// with a User. So, check if there is a device with this $username = RouterDevice.macAddress. If not, then add it as an unassociated device.

// or.. do we just check if the $username looks like a MAC address, then look for it in the routerdevices table, and insert if its not there?


    $query = "UPDATE User, Router set lastLog='{$date}',status= '{$result}'
                WHERE User.customerId = Router.customerId AND
                Router.hostName='{$hostname}' AND
                User.weblogin='{$username}'";
        do {
            $insertdata = & $db->query($query);
            $iserror = false;
            if (PEAR::isError($insertdata)) {
                $msg = $insertdata->getMessage() . "\n";
                $errcode = $insertdata->getCode();
                if ($errcode == DB_ERROR_ACCESS_VIOLATION || $errcode == DB_ERROR_NOSUCHDB ||
                            $errcode == DB_ERROR_NODBSELECTED || $errcode == DB_ERROR ||
                            $errcode == DB_ERROR_NODBSELECTED) {
                    // no connection, etc
                    echo "/5/ ";
                    echo date("Y-m-d H:i | ") . "CODE: " . $insertdata->getCode() . " ";
                    echo $insertdata->getMessage() . " \n";
                    echo $query . " \n";
                    $iserror = false;
                    //$db->disconnect();
                    $db = connectDB();
                } else {
                    echo "/6/ ";
                    echo date("Y-m-d H:i | ") . $insertdata->getMessage() . "\n";
                    echo $query . " \n";
                }
            }
        } while ($iserror ==true);
    }

        function insertDevice (& $db) {
    global $sourceIP, $date, $time, $hostname, $username, $enddeviceIP, $result, $message ;

//      $query = "INSERT into RouterDevice (lastIp,lastSeen,deviceName,routerName,macAddress)
//              VALUES ('{$enddeviceIP}','{$date}','{$username}','{$hostname}','{$username}')";
//      $query = "INSERT into RouterDevice (nickName,lastIp,lastSeen,deviceName,routerName,macAddress)
//              (select distinct description, '{$enddeviceIP}','{$date}','{$username}','{$hostname}','{$username}' from oui where oui = left('{$username}',8))";
//      $query = "INSERT into RouterDevice (nickName,lastIp,lastSeen,deviceName,routerName,macAddress)
//              (select concat(left(description,8),right('{$username}',9)), '{$enddeviceIP}','{$date}','{$username}','{$hostname}','{$username}' from oui where oui = left('{$username}',8))";
        $query ="INSERT into RouterDevice (nickName,lastIp,lastSeen,deviceName,routerName,macAddress,status)
                (select concat(left(description,8),right('{$username}',9)),
                        '{$enddeviceIP}','{$date}','{$username}','{$hostname}','{$username}','{$result}'
                        from oui where oui = left('{$username}',8))
                ON DUPLICATE KEY UPDATE lastIp=VALUES(lastIp),lastSeen=VALUES(lastSeen),status=VALUES(status)";

        echo "query = $query\n";
                                // only router hostname available. No Router Serial or RouterID in log. Hostname must be unique.
                                // table is set up to have the macAddress as a UNIQUE key, to protect against duplicates

        do {
            $insertdata = & $db->query($query);
            $iserror = false;
            if (PEAR::isError($insertdata)) {
                $msg = $insertdata->getMessage() . "\n";
                $errcode = $insertdata->getCode();
                if ($errcode == DB_ERROR_ACCESS_VIOLATION || $errcode == DB_ERROR_NOSUCHDB ||
                            $errcode == DB_ERROR_NODBSELECTED || $errcode == DB_ERROR ||
                            $errcode == DB_ERROR_NODBSELECTED) {
                    // no connection, etc
                    echo "/7/ ";
                    echo date("Y-m-d H:i | ") . "CODE: " . $insertdata->getCode() . " ";
                    echo $insertdata->getMessage() . " \n";
                    echo $query . " \n";
                    $iserror = false;
                    //$db->disconnect();
                    $db = connectDB();
                } else {
                    echo "/8/ ";
                    echo date("Y-m-d H:i | ") . $insertdata->getMessage() . "\n";
                    echo $query . " \n";
                }
            }
        } while ($iserror ==true);
    }

function getUserId (& $db,$UserId) {
    global $username;
    $query = "SELECT RouterDevice.userId from RouterDevice where RouterDevice.macAddress='{$username}'";
        do {
            $selectdata = & $db->query($query);
            $iserror = false;
            if (PEAR::isError($selectdata)) {
                $msg = $selectdata->getMessage() . "\n";
                $errcode = $selectdata->getCode();
                if ($errcode == DB_ERROR_ACCESS_VIOLATION || $errcode == DB_ERROR_NOSUCHDB ||
                            $errcode == DB_ERROR_NODBSELECTED || $errcode == DB_ERROR ||
                            $errcode == DB_ERROR_NODBSELECTED) {
                    // no connection, etc
                    echo "/5/ ";
                    echo date("Y-m-d H:i | ") . "CODE: " . $insertdata->getCode() . " ";
                    echo $selectdata->getMessage() . " \n";
                    echo $query . " \n";
                    $iserror = false;
                    //$db->disconnect();
                    $db = connectDB();
                } else {
                    echo "/6/ ";
                    echo date("Y-m-d H:i | ") . $selectdata->getMessage() . "\n";
                    echo $query . " \n";
                }
            }
        } while ($iserror ==true);
        $selectdata->fetchInto($UserId); // only one UserID from one row will be returned
        return $UserId;
    }

?>
