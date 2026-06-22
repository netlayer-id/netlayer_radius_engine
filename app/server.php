<?php
    $radius = new NetlayerRadius();
    
    $config = new stdClass();
    
    $config->auth_port = 1812;
    $config->acct_port = 1813;
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
