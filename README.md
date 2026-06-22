# NetlayerRadius Engine

PHP RADIUS Client Library with Dictionary Support

## Description

NetlayerRadius is a lightweight PHP library for handling RADIUS (Remote Authentication Dial-In User Service) packets. It supports:
- RADIUS Authentication (PAP, CHAP)
- RADIUS Accounting
- RADIUS Disconnect (RFC 3576)
- RADIUS CoA (Change of Authorization)
- Vendor-Specific Attributes (VSA)
- Custom dictionary loading from text files

## Features

- ✅ Parse and encode RADIUS packets
- ✅ Support for standard RADIUS attributes
- ✅ Vendor-Specific Attributes (MikroTik, Microsoft, Ascend, etc.)
- ✅ PAP and CHAP authentication verification
- ✅ RADIUS Accounting verification
- ✅ Message-Authenticator validation (RFC 2869)
- ✅ Disconnect and CoA request support
- ✅ Dynamic dictionary loading from `.txt` files
- ✅ IP address, IPv6 prefix, uint32/uint64 decoding
- ✅ Utility methods: code generation, byte formatting, duration parsing

## Basic Usage
```php
<?php
    $radius = new NetlayerRadius();
    
    $config = new stdClass();
    
    $config->auth_port = 8000;
    $config->acct_port = 8001;
    $config->debug = true;
    
    $config->radius_secret = 'secret123';
    
    $config->server = [
        "worker_num" => 1,
        "dispatch_mode" => 2,
        "max_request" => 10000,
        "daemonize" => false
    ];
    
    // 3h = 3 hours
    // 1d = 1 days
    $profile_data = [
        "profile1" => [
            "name" => "3 Hours",
            "session_timeout" => $radius->parse_duration("3h"),
            "rate_limit" => "2M/2M",
            "shared_users" => 1
        ],
        "profile2" => [
            "name" => "1 Days",
            "session_timeout" => $radius->parse_duration("1d"),
            "rate_limit" => "2M/2M",
            "shared_users" => 1
        ]
    ];
    
    $user_data = [
        "test1" => [
            "profile_id" => "profile1",
            "password" => "test1",
            "expire" => 0
        ],
        "test2" => [
            "profile_id" => "profile2",
            "password" => "test2",
            "expire" => 0
        ],
        "tplink" => [
            "profile_id" => "profile2",
            "password" => "tplink",
            "expire" => 0
        ]
    ];
    
    // AUTHENTICATION SERVER 
    $auth = new Swoole\Process(function() use($config, $radius, $profile_data, &$user_data){
        $server = new Swoole\Server("0.0.0.0", $config->auth_port, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
        
        $server->set($config->server);
        
        $server->on('packet', function($serv, $data, $client) use($config, $radius, $profile_data, &$user_data){
            $request = $radius->decode($data);
            
            if($config->debug) print_r($request->attributes);
            
            if($request->code == 1){
                $code = 'access_reject';
                $attributes = [];
                
                $username = $request->attributes['User-Name'] ?? null;
                if(isset($user_data[$username])){
                    $user = $user_data[$username];
                    if($user['expire'] > 0 && $user['expire'] < time()){
                        $attributes['Reply-Message'] = "$username - has expired";
                    }else{
                        $password = $user['password'] ?? null;
                        if($radius->verify_pap($password, $config->radius_secret)){
                            $code = 'access_accept';
                        }elseif($radius->verify_chap($password, $config->radius_secret)){
                            $code = 'access_accept';
                        }
                        
                        if($code == 'access_accept'){
                            $session_timeout = 0;
                        
                            $profile = $profile_data[$user['profile_id']] ?? null;
                            if($profile){
                                if($user['expire'] == 0){
                                    $new_expire = time() + $profile['session_timeout'];
                                    $session_timeout = $profile['session_timeout'] ?? 0;
                                    $user_data[$username]['expire'] = $new_expire;
                                }else{
                                    $session_timeout = $user['expire'] - time();
                                }
                                
                                $attributes['Session-Timeout'] = $session_timeout;
                                $attributes['Idle-Timeout'] = 3600;
                                $attributes['Mikrotik-Rate-Limit'] = $profile['rate_limit'] ?? '2M/2M';
                                $attributes['Port-Limit'] = $profile['shared_users'] ?? 1;
                                // more response attributes here...
                            }else{
                                $code = 'access_reject';
                                $attributes['Reply-Message'] = "$username - invalid profile configurations";
                            }
                        }else{
                            $attributes['Reply-Message'] = "$username - invalid password";
                        }
                    }
                }else{
                    $attributes['Reply-Message'] = "$username not found";
                }
                
                $attributes['Message-Authenticator'] = '';
                
                $response = $radius->encode($code, $request->authenticator, $attributes, $config->radius_secret);
                $serv->sendto($client['address'], $client['port'], $response);
            }
        });
        $server->on('start', function($serv) use($config){
            echo "Authentication server started on port : {$config->auth_port}\n";    
        });
        $server->start();
    });
    
    // ACCOUNTING SERVER
    $acct = new Swoole\Process(function() use($config, $radius, $profile_data, &$user_data){
        $server = new Swoole\Server("0.0.0.0", $config->acct_port, SWOOLE_PROCESS, SWOOLE_SOCK_UDP);
        
        $server->set($config->server);
        
        $server->on('packet', function($serv, $data, $client) use($config, $radius, $profile_data, &$user_data){
            $request = $radius->decode($data);
            if($config->debug) print_r($request->attributes);
            
            if($request->code == 4){
                $code = 'accounting_response';
                $attr['Message-Authenticator'] = '';
                
                $response = $radius->encode($code, $request->authenticator, $attr, $config->radius_secret);
                $serv->sendto($client['address'], $client['port'], $response);
            }
        });
        
        $server->on('start', function($serv) use($config){
            echo "Accounting server started on port : {$config->acct_port}\n";    
        });
        
        $server->start();
    });
    
    $auth->start(); // start authentication server
    $acct->start(); // start accounting server
    
    while(Swoole\Process::wait());
```
## How to run ?
```bash
# Allow Execute
chmod +x ./netlayer_x86
chmod +x ./netlayer_arm64

# Run X86
./netlayer_x86

# Run ARM64
./netlayer_arm64
```

### Authentication
```php
$radius = new NetlayerRadius();
$packet = $radius->decode($raw_request);

// Verify PAP password
if ($packet->verify_pap('plain_password', 'secret_key')) {
    echo "PAP authentication successful!";
}

// Verify CHAP password
if ($packet->verify_chap('plain_password', 'secret_key')) {
    echo "CHAP authentication successful!";
}
```

### Accounting Verification 
```php
$radius = new NetlayerRadius();
$packet = $radius->decode($raw_accounting_request);

if ($packet->verify_acct_authenticator($raw_accounting_request, 'secret_key')) {
    echo "Accounting authenticator valid!";
}
```

### Message-Authenticator Verification
```php
$radius = new NetlayerRadius();
$packet = $radius->decode($raw_request);

if ($packet->verify_message_authenticator($raw_request, 'secret_key')) {
    echo "Message-Authenticator valid!";
}
```
### Encode / Build Packet
```php
$radius = new NetlayerRadius();
$attributes = [
    'User-Name' => 'testuser',
    'User-Password' => 'password123',
    'NAS-IP-Address' => '192.168.1.1',
    'Message-Authenticator' => '',
    'Mikrotik-Rate-Limit' => '1M/1M'
];

$secret = 'shared_secret';
$request_authenticator = random_bytes(16);

$packet = $radius->encode('access_request', $request_authenticator, $attributes, $secret);
if ($packet) {
    // Send packet to RADIUS server
    // socket_sendto($socket, $packet, strlen($packet), 0, $server_ip, $port);
}
```

### Disconnect Request (RFC 3576)
```php
$radius = new NetlayerRadius();
$packet = $radius->disconnect(
    '192.168.1.1',      // NAS IP
    '192.168.100.254',  // Framed IP
    'secret_key',       // NAS Secret
    'session123',       // Session ID
    'username'          // Username
);

// Send packet to RADIUS server (port 3799)
```

### CoA Request (RFC 5176)
```php
$radius = new NetlayerRadius();
$packet = $radius->coa_request(
    '192.168.1.1',      // NAS IP
    '192.168.100.254',  // Framed IP
    'secret_key',       // NAS Secret
    'session123',       // Session ID
    'username',         // Username
    [
        'Session-Timeout' => 3600,
        'Idle-Timeout' => 600,
        'Mikrotik-Rate-Limit' => '2M/2M'
    ]
);
```

### Utility Methods
```php
$radius = new NetlayerRadius();

// Generate random code
$code = $radius->generate_code(8, 2);
// Type: 0=Uppercase, 1=Digits, 2=Alphanumeric, 3=Lowercase, 4=Lowercase+Digits

// Format bytes
echo $radius->format_bytes(2048); // 2 KB
echo $radius->format_bytes(1048576); // 1 MB

// Parse duration
echo $radius->parse_duration('5m'); // 300
echo $radius->parse_duration('2h'); // 7200
echo $radius->parse_duration('1d'); // 86400

// Format duration
echo $radius->format_duration(3600); // 1h
echo $radius->format_duration(120); // 2m
echo $radius->format_duration(86400); // 1d
```

