<?php

namespace OAuth2\OpenID\ResponseType;

use OAuth2\Encryption\EncryptionInterface;
use OAuth2\Encryption\Jwt;
use OAuth2\Storage\PublicKeyInterface;
use OAuth2\OpenID\Storage\UserClaimsInterface;
use LogicException;

class IdToken implements IdTokenInterface
{
    /**
    * @var UserClaimsInterface
    */
    protected $userClaimsStorage;
    /**
    * @var PublicKeyInterface
    */
    protected $publicKeyStorage;

    /**
    * @var array
    */
    protected $config;

    /**
    * @var EncryptionInterface
    */
    protected $encryptionUtil;

    /** [dnc128']
    * @var string
    */
    public const ENFORCEDCLAIMS = 'iss sub aud iat exp auth_time kid';

    /**
    * [dnc[140]
    * 
    * @var mixed
    */
    protected $authcode;

    /**
    * [dnc140]
    * 
    * @var mixed
    */
    protected $access_token;


    /**
    * Constructor
    *
    * @param UserClaimsInterface $userClaimsStorage
    * @param PublicKeyInterface $publicKeyStorage
    * @param array $config
    * @param EncryptionInterface $encryptionUtil
    * @throws LogicException
    */
    public function __construct(UserClaimsInterface $userClaimsStorage, PublicKeyInterface $publicKeyStorage, array $config = array(), EncryptionInterface $encryptionUtil = null)
    {
        $this->userClaimsStorage = $userClaimsStorage;
        $this->publicKeyStorage = $publicKeyStorage;
        if (is_null($encryptionUtil)) {
            $encryptionUtil = new Jwt();
        }
        $this->encryptionUtil = $encryptionUtil;

        if (!isset($config['issuer'])) {
            throw new LogicException('config parameter "issuer" must be set');
        }
        $this->config = array_merge(array(
            'id_lifetime' => 3600,
            ), $config);
    }

    /**
    * @param array $params
    * @param null $userInfo
    * @return array|mixed
    */
    public function getAuthorizeResponse($params, $userInfo = null)
    { 
        // build the URL to redirect to
        $result = array('query' => array());
        $params += array('scope' => null, 'state' => null, 'nonce' => null);

        // create the id token.
        list($user_id, $auth_time) = $this->getUserIdAndAuthTime($userInfo);
        $userClaims = $this->userClaimsStorage->getUserClaims($user_id, $params['scope']);
        $id_token = $this->createIdToken($params['client_id'], $userInfo, $params['nonce'], $userClaims);  //[dnc140]
        $result["fragment"] = array('id_token' => $id_token);
        if (isset($params['state'])) {
            $result["fragment"]["state"] = $params['state'];
        }

        //[dnc143] We need an entry in the access token table without which we would have no record of the successful authentication
        global $controller;   // \OAuthSD\Controller\AuthorizeController
        $access_token = uniqid('idT_');
        $client_id = $params['client_id'];
        $expires = date('Y-m-d H:i:s', $auth_time + ACCESS_TOKEN_LIFETIME);
        $scope = $params['scope'];
        $acr = $params['acr'];
        $stmt = $controller->server->pdoinstance->prepare(sprintf('INSERT INTO %s (access_token, client_id, user_id, expires, scope, acr) VALUES(:access_token, :client_id, :user_id, :expires, :scope, :acr)', $controller->server->storage_config['access_token_table']));    
        $void = $stmt->execute(compact('access_token', 'client_id','user_id', 'expires', 'scope', 'acr'));

        return array($params['redirect_uri'], $result);
    }

    /**
    * Create id token
    * @see https://openid.net/specs/openid-connect-core-1_0.html#IDToken
    *
    * @param string $client_id
    * @param mixed  $userInfo
    * @param mixed  $nonce
    * @param mixed  $userClaims
    * @param mixed  $access_token
    * @param mixed  $authcode [dnc140]
    * @return mixed|string
    */
    public function createIdToken($client_id, $userInfo, $nonce = null, $userClaims = null)    //[dnc140]
    { 
        // pull auth_time from user info if supplied
        list($user_id, $auth_time, $acr) = $this->getUserIdAndAuthTime($userInfo);     //[dnc91h] acr too

        if ( is_null($acr) ) $acr = ( LOGIN_WITH_TFA )? '2' : '1';    //[dnc4a] default acr value

        //[dnc4] Calculate kid. Simply the public key hash
        $public = $this->publicKeyStorage->getPublicKey($client_id);        
        $kid = md5($public);  // computed on server stored value

        $token = array(       //[dnc128'] define ENFORCEDCLAIMS consistently  
            'iss'        => $this->config['issuer'],
            'sub'        => $user_id,
            'aud'        => $client_id,
            'iat'        => time(),
            'exp'        => time() + $this->config['id_lifetime'],
            'auth_time'  => $auth_time,
            'kid'        => $kid, //[dnc4]
            'acr'        => $acr, //[dnc91h]
        );

        if ($nonce) {
            $token['nonce'] = $nonce;
        }

        if ($userClaims) {
            $token += $userClaims;
        }

        if ($this->access_token) {  //[dnc140]
            // @see https://openid.net/specs/openid-connect-core-1_0.html#ImplicitTokenValidation
            $token['at_hash'] = $this->createAtHash($this->access_token, $client_id);
        }

        if ($this->authcode) {  //[dnc140]
            // @see https://openid.net/specs/openid-connect-core-1_0.html#CodeValidation
            $token['c_hash'] = $this->createAtHash($this->authcode, $client_id);
        }

        //[dnc13'][dnc69] Add extra payload
        if (isset($this->config['jwt_extra_payload_callable'])) {
            if (!is_callable($this->config['jwt_extra_payload_callable'])) {
                throw new \InvalidArgumentException('jwt_extra_payload_callable is not callable');
            }

            $extra = call_user_func($this->config['jwt_extra_payload_callable'], $client_id, $user_id, null);

            if (!is_array($extra)) {
                throw new \InvalidArgumentException('jwt_extra_payload_callable must return array');
            }

            $token = array_merge($extra, $token);
        }

        return $this->encodeToken($token, $client_id);
    }

    /**
    * see https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.3.2.11
    * @param $access_token
    * @param null $client_id
    * @return mixed|string
    */
    protected function createAtHash($access_token, $client_id = null)
    {
        // maps HS256 and RS256 to sha256, etc.
        $algorithm = $this->publicKeyStorage->getEncryptionAlgorithm($client_id);
        $hash_algorithm = 'sha' . substr($algorithm, 2);
        $hash = hash($hash_algorithm, $access_token, true);
        $at_hash = substr($hash, 0, strlen($hash) / 2);

        return $this->encryptionUtil->urlSafeB64Encode($at_hash);
    }


    /**
    * @param array $token
    * @param null $client_id
    * @return mixed|string
    */
    protected function encodeToken(array $token, $client_id = null)
    {
        $private_key = $this->publicKeyStorage->getPrivateKey($client_id);    //TODO: default key if null
        $algorithm = $this->publicKeyStorage->getEncryptionAlgorithm($client_id);

        return $this->encryptionUtil->encode($token, $private_key, $algorithm);
    }

    /**
    * @param $userInfo
    * @return array
    * @throws LogicException
    */
    private function getUserIdAndAuthTime($userInfo)
    {
        $auth_time = null;

        // support an array for user_id / auth_time
        if (is_array($userInfo)) {
            if (!isset($userInfo['user_id'])) {
                throw new LogicException('if $user_id argument is an array, user_id index must be set');
            }

            $auth_time = isset($userInfo['auth_time']) ? $userInfo['auth_time'] : null;
            $user_id = $userInfo['user_id'];
        } else {
            $user_id = $userInfo;
        }

        if (is_null($auth_time)) {
            $auth_time = time();
        }

        // userInfo is a scalar, and so this is the $user_id. Auth Time is null
        return array($user_id, $auth_time);
    }

    /**
    * [dnc140]
    * 
    * @param mixed $access_token
    */
    public function set_access_token( $access_token) 
    {
        $this->access_token = $access_token;
    }

    /**
    * [dnc140]
    * 
    * @param mixed $authcode
    */
    public function set_authcode( $authcode) 
    {
        $this->authcode = $authcode;
    }

}
