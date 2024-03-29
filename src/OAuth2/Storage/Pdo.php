<?php

namespace OAuth2\Storage;

use OAuth2\OpenID\Storage\UserClaimsInterface;
use OAuth2\OpenID\Storage\AuthorizationCodeInterface as OpenIDAuthorizationCodeInterface;
use InvalidArgumentException;

/**
* Simple PDO storage for all storage types
*
* NOTE: This class is meant to get users started
* quickly. If your application requires further
* customization, extend this class or create your own.
*
* NOTE: Passwords are stored in plaintext, which is never
* a good idea.  Be sure to override this for your application
*
* @author Brent Shaffer <bshafs at gmail dot com>
*/
class Pdo implements
AuthorizationCodeInterface,
AccessTokenInterface,
ClientCredentialsInterface,
UserCredentialsInterface,
RefreshTokenInterface,
JwtBearerInterface,
ScopeInterface,
PublicKeyInterface,
UserClaimsInterface,
OpenIDAuthorizationCodeInterface
{
    /**
    * @var \PDO
    */
    protected $db;

    /**
    * @var array
    */
    protected $config;

    /**
    * @param mixed $connection
    * @param array $config
    *
    * @throws InvalidArgumentException
    */
    public function __construct($connection, $config = array())
    {
        if (!$connection instanceof \PDO) {
            if (is_string($connection)) {
                $connection = array('dsn' => $connection);
            }
            if (!is_array($connection)) {
                throw new \InvalidArgumentException('First argument to OAuth2\Storage\Pdo must be an instance of PDO, a DSN string, or a configuration array');
            }
            if (!isset($connection['dsn'])) {
                throw new \InvalidArgumentException('configuration array must contain "dsn"');
            }
            // merge optional parameters
            $connection = array_merge(array(
                'username' => null,
                'password' => null,
                'options' => array(),
                ), $connection);
            $connection = new \PDO($connection['dsn'], $connection['username'], $connection['password'], $connection['options']);
        }
        $this->db = $connection;

        // debugging
        $connection->setAttribute(\PDO::ATTR_ERRMODE, \PDO::ERRMODE_EXCEPTION);

        $this->config = array_merge(array(
            'client_table' => 'oauth_clients',
            'access_token_table' => 'oauth_access_tokens',
            'refresh_token_table' => 'oauth_refresh_tokens',
            'code_table' => 'oauth_authorization_codes',
            'user_table' => 'oauth_users',
            'jwt_table'  => 'oauth_jwt',
            'jti_table'  => 'oauth_jti',
            'scope_table'  => 'oauth_scopes',
            'public_key_table'  => 'oauth_public_keys',
            ), $config);
    }

    /**
    * @param string $client_id
    * @param null|string $client_secret
    * @return bool
    */
    public function checkClientCredentials($client_id, $client_secret = null)
    {
        //[dnc3]
        $client_id = urldecode($client_id);
        $client_secret = urldecode($client_secret);

        $stmt = $this->db->prepare(sprintf('SELECT * from %s where client_id = :client_id', $this->config['client_table']));
        $stmt->execute(compact('client_id'));
        $result = $stmt->fetch(\PDO::FETCH_ASSOC);

        // make this extensible
        return $result && $result['client_secret'] == $client_secret;
    }

    /**
    * @param string $client_id
    * @return bool
    */
    public function isPublicClient($client_id)
    {
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where client_id = :client_id', $this->config['client_table']));
        $stmt->execute(compact('client_id'));

        if (!$result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return false;
        }

        return empty($result['client_secret']);
    }

    /**
    * @param string $client_id
    * @return array|mixed
    */
    public function getClientDetails($client_id)
    {
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where client_id = :client_id', $this->config['client_table']));
        $stmt->execute(compact('client_id'));

        return $stmt->fetch(\PDO::FETCH_ASSOC);
    }

    /**
    * @param string $client_id
    * @param null|string $client_secret
    * @param null|string $redirect_uri
    * @param null|array  $grant_types
    * @param null|string $scope
    * @param null|string $user_id
    * @return bool
    */
    public function setClientDetails($client_id, $client_secret = null, $redirect_uri = null, $grant_types = null, $scope = null, $user_id = null)
    {
        // if it exists, update it.
        if ($this->getClientDetails($client_id)) {
            $stmt = $this->db->prepare($sql = sprintf('UPDATE %s SET client_secret=:client_secret, redirect_uri=:redirect_uri, grant_types=:grant_types, scope=:scope, user_id=:user_id where client_id=:client_id', $this->config['client_table']));
        } else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO %s (client_id, client_secret, redirect_uri, grant_types, scope, user_id) VALUES (:client_id, :client_secret, :redirect_uri, :grant_types, :scope, :user_id)', $this->config['client_table']));
        }

        return $stmt->execute(compact('client_id', 'client_secret', 'redirect_uri', 'grant_types', 'scope', 'user_id'));
    }

    /**
    * @param $client_id
    * @param $grant_type
    * @return bool
    */
    public function checkRestrictedGrantType($client_id, $grant_type)
    {
        $details = $this->getClientDetails($client_id);
        if (isset($details['grant_types'])) {
            $grant_types = explode(' ', $details['grant_types']);

            return in_array($grant_type, (array) $grant_types);
        }

        // if grant_types are not defined, then none are restricted
        return true;
    }

    /**
    * @param string $access_token
    * @return array|bool|mixed|null
    */
    public function getAccessToken($access_token)
    {
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where access_token = :access_token', $this->config['access_token_table']));

        $token = $stmt->execute(compact('access_token'));
        if ($token = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            // convert date string back to timestamp
            $token['expires'] = strtotime($token['expires']);
        }

        return $token;
    }

    /**
    * @param string $access_token
    * @param mixed  $client_id
    * @param mixed  $userinfo  //[dnc49] may be array or scalar. ???
    * @param int    $expires
    * @param string $scope
    * @return bool
    */
    public function setAccessToken($access_token, $client_id, $userinfo, $expires, $scope = null, $acr = null)    //[dnc91g]
    {   //DebugBreak("435347910947900005@127.0.0.1;d=1");  //DEBUG
        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        $user_id = (is_array($userinfo)? $userinfo['user_id'] : $userinfo);   //[dnc49]  ???

        // if it exists, update it.
        if ($this->getAccessToken($access_token)) {
            $stmt = $this->db->prepare(sprintf('UPDATE %s SET client_id=:client_id, expires=:expires, user_id=:user_id, scope=:scope, acr=:acr where access_token=:access_token', $this->config['access_token_table']));   //[dnc91g]
        } else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO %s (access_token, client_id, expires, user_id, scope, acr) VALUES (:access_token, :client_id, :expires, :user_id, :scope, :acr)', $this->config['access_token_table']));  //[dnc91g]
        }

        return $stmt->execute(compact('access_token', 'client_id', 'user_id', 'expires', 'scope', 'acr'));    //[dnc91g]
    }

    /**
    * @param $access_token
    * @return bool
    */
    public function unsetAccessToken($access_token)
    {
        $stmt = $this->db->prepare(sprintf('DELETE FROM %s WHERE access_token = :access_token', $this->config['access_token_table']));

        $stmt->execute(compact('access_token'));

        return $stmt->rowCount() > 0;
    }

    /* OAuth2\Storage\AuthorizationCodeInterface */
    /**
    * @param string $code
    * @return mixed
    */
    public function getAuthorizationCode($code)
    {
        $stmt = $this->db->prepare(sprintf('SELECT * from %s where authorization_code = :code', $this->config['code_table']));
        $stmt->execute(compact('code'));

        if ($code = $stmt->fetch(\PDO::FETCH_ASSOC)) {        //TODO : ne pas mélanger code et code[] !
            // convert date string back to timestamp
            $code['expires'] = strtotime($code['expires']);
        }

        return $code;
    }

    /**
    * @param string $code
    * @param mixed  $client_id
    * @param mixed  $userinfo  //[dnc49] keep $user_id notation for scalar
    * @param string $redirect_uri
    * @param int    $expires
    * @param string $scope
    * @param string $id_token
    * @return bool|mixed
    */
    public function setAuthorizationCode($code, $client_id, $userinfo, $redirect_uri, $expires, $scope = null, $id_token = null, $acr=null, $code_challenge = null, $code_challenge_method = null) //[pkce'] [dnc91g]
    {
        $user_id = (is_array($userinfo)? $userinfo['user_id'] : $userinfo);   //[dnc49]

        /* [dnc1] 
        if (func_num_args() > 6) {
        // we are calling with an id token
        return call_user_func_array(array($this, 'setAuthorizationCodeWithIdToken'), func_get_args());
        } */ 
        if ( !is_null($id_token) ) {  //[dnc1] 
            return $this->setAuthorizationCodeWithIdToken($code, $client_id, $user_id, $redirect_uri, $expires, $scope, $id_token, $acr, $code_challenge, $code_challenge_method); //[pkce'] [dnc91g]
        }

        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $stmt = $this->db->prepare($sql = sprintf('UPDATE %s SET client_id=:client_id, user_id=:user_id, redirect_uri=:redirect_uri, expires=:expires, scope=:scope, acr=:acr, code_challenge=:code_challenge, code_challenge_method=:code_challenge_method where authorization_code=:code', $this->config['code_table']));   //[pkce'] [dnc91g]
        } else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO %s (authorization_code, client_id, user_id, redirect_uri, expires, scope, acr, code_challenge, code_challenge_method) VALUES (:code, :client_id, :user_id, :redirect_uri, :expires, :scope, :acr, :code_challenge, :code_challenge_method)', $this->config['code_table']));   //[pkce'] [dnc91g]
        }

        return $stmt->execute(compact('code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'scope', 'acr', 'code_challenge', 'code_challenge_method'));    //[pkce'] [dnc91g]
    }

    /**
    * @param string $code
    * @param mixed  $client_id
    * @param mixed  $userinfo  //[dnc49] keep $user_id notation for scalar
    * @param string $redirect_uri
    * @param string $expires
    * @param string $scope
    * @param string $id_token
    * @return bool
    */
    private function setAuthorizationCodeWithIdToken($code, $client_id, $userinfo, $redirect_uri, $expires, $scope = null, $id_token = null, $acr=null, $code_challenge = null, $code_challenge_method = null) //[pkce']  [dnc91g]
    {
        $user_id = (is_array($userinfo)? $userinfo['user_id'] : $userinfo);   //[dnc49]

        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        // if it exists, update it.
        if ($this->getAuthorizationCode($code)) {
            $stmt = $this->db->prepare($sql = sprintf('UPDATE %s SET client_id=:client_id, user_id=:user_id, redirect_uri=:redirect_uri, expires=:expires, scope=:scope, id_token =:id_token, acr=:acr, code_challenge=:code_challenge, code_challenge_method=:code_challenge_method where authorization_code=:code', $this->config['code_table']));  //[pkce']  [dnc91g]
        } else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO %s (authorization_code, client_id, user_id, redirect_uri, expires, scope, id_token, acr, code_challenge, code_challenge_method) VALUES (:code, :client_id, :user_id, :redirect_uri, :expires, :scope, :id_token, :acr, :code_challenge, :code_challenge_method)', $this->config['code_table']));   //[pkce']  [dnc91g]
        }

        return $stmt->execute(compact('code', 'client_id', 'user_id', 'redirect_uri', 'expires', 'scope', 'id_token', 'acr', 'code_challenge', 'code_challenge_method'));  //[pkce']  [dnc91g]
    }

    /**
    * @param string $code
    * @return bool
    * [dnc50] Instead of deleting, set expires to Null.
    */
    public function expireAuthorizationCode($code)
    {
        //[dnc50] $stmt = $this->db->prepare(sprintf('DELETE FROM %s WHERE authorization_code = :code', $this->config['code_table']));
        $stmt = $this->db->prepare(sprintf('UPDATE %s SET expires=NULL WHERE authorization_code = :code', $this->config['code_table']));
        return $stmt->execute(compact('code'));
    }

    /**
    * @param string $username
    * @param string $password
    * @return bool
    */
    public function checkUserCredentials($username, $password)
    {
        if ($user = $this->getUser($username)) {
            return $this->checkPassword($user, $password);
        }

        return false;
    }

    /**
    * @param string $username
    * @return array|bool
    */
    public function getUserDetails($username)
    {
        return $this->getUser($username);
    }

    /**
    * @param mixed  $userinfo  //[dnc49] keep $user_id notation for scalar
    * @param string $claims
    * @return array|bool
    */
    public function getUserClaims($userinfo, $claims)
    {
        $user_id = (is_array($userinfo)? $userinfo['user_id'] : $userinfo);   //[dnc49]

        if (!$userDetails = $this->getUserDetails($user_id)) {
            return false;
        }

        $claims = explode(' ', trim($claims));
        $userClaims = array();

        // for each requested claim, if the user has the claim, set it in the response
        $validClaims = explode(' ', self::VALID_CLAIMS);
        foreach ($validClaims as $validClaim) {
            if (in_array($validClaim, $claims)) {
                if ($validClaim == 'address') {
                    // address is an object with subfields
                    $userClaims['address'] = $this->getUserClaim($validClaim, @$userDetails['address'] ?: $userDetails);
                } else {
                    $userClaims = array_merge($userClaims, $this->getUserClaim($validClaim, $userDetails));
                }
            }
        }

        return $userClaims;
    }

    /**
    * @param string $claim
    * @param array  $userDetails
    * @return array
    */
    protected function getUserClaim($claim, $userDetails)
    {
        $userClaims = array();
        $claimValuesString = constant(sprintf('self::%s_CLAIM_VALUES', strtoupper($claim)));     // voir [dnc2']
        $claimValues = explode(' ', $claimValuesString);

        foreach ($claimValues as $value) {
            $userClaims[$value] = isset($userDetails[$value]) ? $userDetails[$value] : null;
        }

        return $userClaims;
    }

    /**
    * @param string $refresh_token
    * @return bool|mixed
    */
    public function getRefreshToken($refresh_token)
    {
        $stmt = $this->db->prepare(sprintf('SELECT * FROM %s WHERE refresh_token = :refresh_token', $this->config['refresh_token_table']));

        $token = $stmt->execute(compact('refresh_token'));
        if ($token = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            // convert expires to epoch time
            $token['expires'] = strtotime($token['expires']);
        }

        return $token;
    }

    /**
    * @param string $refresh_token
    * @param mixed  $client_id
    * @param mixed  $userinfo  //[dnc49] keep $user_id notation for scalar
    * @param string $expires
    * @param string $scope
    * @return bool
    */
    public function setRefreshToken($refresh_token, $client_id, $userinfo, $expires, $scope = null)
    {
        $user_id = (is_array($userinfo)? $userinfo['user_id'] : $userinfo);   //[dnc49]

        // convert expires to datestring
        $expires = date('Y-m-d H:i:s', $expires);

        $stmt = $this->db->prepare(sprintf('INSERT INTO %s (refresh_token, client_id, user_id, expires, scope) VALUES (:refresh_token, :client_id, :user_id, :expires, :scope)', $this->config['refresh_token_table']));

        return $stmt->execute(compact('refresh_token', 'client_id', 'user_id', 'expires', 'scope'));
    }

    /**
    * @param string $refresh_token
    * @return bool
    */
    public function unsetRefreshToken($refresh_token)
    {
        $stmt = $this->db->prepare(sprintf('DELETE FROM %s WHERE refresh_token = :refresh_token', $this->config['refresh_token_table']));

        $stmt->execute(compact('refresh_token'));

        return $stmt->rowCount() > 0;
    }

    /**
    * plaintext passwords are bad!  Override this for your application
    *
    * @param array $user
    * @param string $password
    * @return bool
    */
    protected function checkPassword($user, $password)
    {
        //[dnc100] passwords must be hashed with password_hash() function.
        $Ok = password_verify($password, $user['password']);  
        if ( $Ok ) {
            return $Ok;
        } else {
            // try deprecated method
            return $user['password'] == $this->hashPassword($password);
        }        
    }

    // use a secure hashing algorithm when storing passwords. Override this for your application
    //[dnc100] deprecated
    protected function hashPassword($password)
    {
        return sha1($password);
    }

    /**
    * @param string $username
    * @return array|bool
    */
    public function getUser($username)
    {

        $user_table = $this->config['user_table'];
        if ( $user_table == TABLE_PREFIX . 'auteurs' ) {  //[spip] buy.dnc.global utilise la table de SPIP
            $stmt = $this->db->prepare($sql = sprintf('SELECT * from %s where login=:username', $this->config['user_table']));
            $stmt->execute(array('username' => $username));     
        } else if ( $user_table == TABLE_PREFIX . 'users' ) {  // OAuthSD utilise la table OIDC standard
            $stmt = $this->db->prepare($sql = sprintf('SELECT * from %s where login=:username', $this->config['user_table']));
            $stmt->execute(array('username' => $username));    
        } // sinon table inconnue     

        if (!$userInfo = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return false;
        }

        // the default behavior is to use "username" as the user_id
        return array_merge(array(
            'user_id' => $username
            ), $userInfo);
    }

    /**
    * plaintext passwords are bad!  Override this for your application
    *
    * @param string $username
    * @param string $password
    * @param string $firstName
    * @param string $lastName
    * @return bool
    */
    public function setUser($username, $password, $firstName = null, $lastName = null)
    {
        // do not store in plaintext
        $password = $this->hashPassword($password);

        // if it exists, update it.
        if ($this->getUser($username)) {
            $stmt = $this->db->prepare($sql = sprintf('UPDATE %s SET password=:password, first_name=:firstName, last_name=:lastName where username=:username', $this->config['user_table']));
        } else {
            $stmt = $this->db->prepare(sprintf('INSERT INTO %s (username, password, first_name, last_name) VALUES (:username, :password, :firstName, :lastName)', $this->config['user_table']));
        }

        return $stmt->execute(compact('username', 'password', 'firstName', 'lastName'));
    }

    /**
    * @param string $scope
    * @return bool
    */
    public function scopeExists($scope)
    {
        $scope = explode(' ', $scope);
        $whereIn = implode(',', array_fill(0, count($scope), '?'));
        $stmt = $this->db->prepare(sprintf('SELECT count(scope) as count FROM %s WHERE scope IN (%s)', $this->config['scope_table'], $whereIn));
        $stmt->execute($scope);

        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result['count'] == count($scope);
        }

        return false;
    }

    /**
    * @param mixed $client_id
    * @return null|string
    */
    public function getDefaultScope($client_id = null)
    {
        $stmt = $this->db->prepare(sprintf('SELECT scope FROM %s WHERE is_default=:is_default', $this->config['scope_table']));
        $stmt->execute(array('is_default' => true));

        if ($result = $stmt->fetchAll(\PDO::FETCH_ASSOC)) {
            $defaultScope = array_map(function ($row) {
                return $row['scope'];
                }, $result);

            return implode(' ', $defaultScope);
        }

        return null;
    }

    /**
    * @param mixed $client_id
    * @param $subject
    * @return string
    */
    public function getClientKey($client_id, $subject)
    {
        $stmt = $this->db->prepare($sql = sprintf('SELECT public_key from %s where client_id=:client_id AND subject=:subject', $this->config['jwt_table']));

        $stmt->execute(array('client_id' => $client_id, 'subject' => $subject));

        return $stmt->fetchColumn();
    }

    /**
    * @param mixed $client_id
    * @return bool|null
    */
    public function getClientScope($client_id)
    {
        if (!$clientDetails = $this->getClientDetails($client_id)) {
            return false;
        }

        if (isset($clientDetails['scope'])) {
            return $clientDetails['scope'];
        }

        return null;
    }

    /**
    * @param mixed $client_id
    * @param $subject
    * @param $audience
    * @param $expires
    * @param $jti
    * @return array|null
    */
    public function getJti($client_id, $subject, $audience, $expires, $jti)
    {
        $stmt = $this->db->prepare($sql = sprintf('SELECT * FROM %s WHERE issuer=:client_id AND subject=:subject AND audience=:audience AND expires=:expires AND jti=:jti', $this->config['jti_table']));

        $stmt->execute(compact('client_id', 'subject', 'audience', 'expires', 'jti'));

        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return array(
                'issuer' => $result['issuer'],
                'subject' => $result['subject'],
                'audience' => $result['audience'],
                'expires' => $result['expires'],
                'jti' => $result['jti'],
            );
        }

        return null;
    }

    /**
    * @param mixed $client_id
    * @param $subject
    * @param $audience
    * @param $expires
    * @param $jti
    * @return bool
    */
    public function setJti($client_id, $subject, $audience, $expires, $jti)
    {
        $stmt = $this->db->prepare(sprintf('INSERT INTO %s (issuer, subject, audience, expires, jti) VALUES (:client_id, :subject, :audience, :expires, :jti)', $this->config['jti_table']));

        return $stmt->execute(compact('client_id', 'subject', 'audience', 'expires', 'jti'));
    }

    /**
    * @param mixed $client_id
    * @return mixed
    */
    public function getPublicKey($client_id = null)
    {
        $stmt = $this->db->prepare($sql = sprintf('SELECT public_key FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));

        $stmt->execute(compact('client_id'));
        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result['public_key'];
        }
    }

    /**
    * @param mixed $client_id
    * @return mixed
    */
    public function getPrivateKeyData($client_id = null) //[dnc4] added
    {
        $stmt = $this->db->prepare($sql = sprintf('SELECT * FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));

        $stmt->execute(compact('client_id'));
        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result;
        }
    }

    /**
    * @param mixed $client_id
    * @return mixed
    */
    public function getPrivateKey($client_id = null)
    {
        $stmt = $this->db->prepare($sql = sprintf('SELECT private_key FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));

        $stmt->execute(compact('client_id'));
        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result['private_key'];
        }
    }

    /**
    * @param mixed $client_id
    * @return string
    */
    public function getEncryptionAlgorithm($client_id = null)
    {
        $stmt = $this->db->prepare($sql = sprintf('SELECT encryption_algorithm FROM %s WHERE client_id=:client_id OR client_id IS NULL ORDER BY client_id IS NOT NULL DESC', $this->config['public_key_table']));

        $stmt->execute(compact('client_id'));
        if ($result = $stmt->fetch(\PDO::FETCH_ASSOC)) {
            return $result['encryption_algorithm'];
        }

        return 'RS256';
    }

    /**
    * DDL to create OAuth2 database and tables for PDO storage
    *
    * @see https://github.com/dsquier/oauth2-server-php-mysql
    *
    * @param string $dbName
    * @return string
    */

    /*[dnc57] 2019/06/16 - Bug : Le flux client credentials produit un access_token de type JWT (et pourquoi donc ???).
    Le champ access_token de la table access_tokens est trop court pour un JWT. Le token se trouve tronqué et on obtient une erreur d'index primaire dupliqué (parce que le JWT a toujours le même header).
    Porté la longeur de 40 à 1000 (longueur maximale d'une clé d'index). 
    */
    //[dnc91d] [dnc136b] [pkce] [SPIP]
    public function getBuildSql($dbName = 'oauth2_server_php')
    {
        $sql = "
        CREATE TABLE {$this->config['client_table']} (
        client_id             VARCHAR(80)   NOT NULL,
        client_secret         VARCHAR(80),
        redirect_uri          VARCHAR(2000),
        grant_types           VARCHAR(80),
        scope                 VARCHAR(4000),
        user_id               VARCHAR(80)
        );
        ALTER TABLE spip_clients
        ADD PRIMARY KEY (id_client),
        ADD UNIQUE KEY client_id (client_id),
        ADD KEY statut (statut);
        ALTER TABLE spip_clients
        MODIFY id_client bigint(21) NOT NULL AUTO_INCREMENT;

        CREATE TABLE {$this->config['access_token_table']} (
        access_token varchar(1000) NOT NULL,
        client_id varchar(80) NOT NULL,
        user_id varchar(255) DEFAULT NULL,
        expires timestamp NOT NULL DEFAULT current_timestamp(),
        scope varchar(2000) DEFAULT NULL,
        acr smallint(6) DEFAULT NULL,
        auth_time timestamp NOT NULL DEFAULT current_timestamp()
        );
        ALTER TABLE spip_access_tokens
        ADD PRIMARY KEY (access_token),
        ADD KEY clientuser (client_id,user_id);

        CREATE TABLE {$this->config['code_table']} (
        authorization_code varchar(80) NOT NULL,
        client_id varchar(80) NOT NULL,
        user_id varchar(255) DEFAULT NULL,
        redirect_uri varchar(2000) DEFAULT NULL,
        expires timestamp NULL DEFAULT NULL,
        scope varchar(2000) DEFAULT NULL,
        id_token text DEFAULT NULL,
        code_challenge varchar(256) DEFAULT NULL,
        code_challenge_method varchar(128) DEFAULT NULL,
        acr smallint(6) DEFAULT NULL
        );
        ALTER TABLE {$this->config['code_table']}
        ADD PRIMARY KEY (authorization_code),
        ADD KEY client_user_idx (client_id,user_id);

        CREATE TABLE {$this->config['refresh_token_table']} (
        refresh_token       VARCHAR(40)    NOT NULL,
        client_id           VARCHAR(80)    NOT NULL,
        user_id             VARCHAR(80),
        expires             TIMESTAMP      NOT NULL,
        scope               VARCHAR(4000),
        );
        ALTER TABLE {$this->config['refresh_token_table']}
        ADD PRIMARY KEY (refresh_token);

        CREATE TABLE {$this->config['user_table']} (
        id_user bigint(20) NOT NULL,
        username varchar(255) DEFAULT NULL,
        password varchar(2000) DEFAULT NULL,
        given_name varchar(255) DEFAULT NULL,
        middle_name varchar(255) DEFAULT NULL,
        family_name varchar(255) DEFAULT NULL,
        nickname varchar(255) DEFAULT NULL,
        preferred_username varchar(32) DEFAULT NULL,
        profil varchar(255) DEFAULT NULL,
        picture varchar(255) DEFAULT NULL,
        website varchar(255) DEFAULT NULL,
        email varchar(255) DEFAULT NULL,
        email_verified tinyint(1) DEFAULT NULL,
        gender varchar(16) DEFAULT NULL,
        birthdate varchar(64) DEFAULT NULL,
        zoneinfo varchar(64) DEFAULT NULL,
        locale varchar(16) DEFAULT NULL,
        phone_number varchar(64) DEFAULT NULL,
        phone_number_verified tinyint(1) DEFAULT NULL,
        address varchar(1024) DEFAULT NULL,
        street_address varchar(255) DEFAULT NULL,
        locality varchar(63) DEFAULT NULL,
        region varchar(63) DEFAULT NULL,
        postal_code varchar(31) DEFAULT NULL,
        country varchar(63) DEFAULT NULL,
        updated_time datetime DEFAULT '0000-00-00 00:00:00',
        created_time datetime DEFAULT NULL,
        statut varchar(20) NOT NULL DEFAULT 'publie',
        maj timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
        composition varchar(255) NOT NULL DEFAULT '',
        composition_lock tinyint(1) NOT NULL DEFAULT 0,
        profile varchar(256) DEFAULT NULL,
        comment text DEFAULT NULL,
        scope varchar(4000) DEFAULT NULL,
        verified tinyint(1) DEFAULT NULL
        );
        ALTER TABLE {$this->config['user_table']}
        ADD PRIMARY KEY (id_user),
        ADD UNIQUE KEY email (email),
        ADD UNIQUE KEY username (username) USING BTREE,
        ADD KEY statut (statut);
        ALTER TABLE {$this->config['user_table']}
        MODIFY id_user bigint(20) NOT NULL AUTO_INCREMENT;


        CREATE TABLE {$this->config['scope_table']} (
        id_scope bigint(21) NOT NULL,
        scope varchar(80) NOT NULL,
        is_default tinyint(1) DEFAULT NULL,
        scope_description text DEFAULT NULL,
        statut varchar(20) NOT NULL DEFAULT '0',
        maj timestamp NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
        date_publication datetime NOT NULL DEFAULT '0000-00-00 00:00:00'
        );
        ALTER TABLE {$this->config['scope_table']}
        ADD PRIMARY KEY (id_scope),
        ADD KEY scope (scope);
        ALTER TABLE {$this->config['scope_table']}
        MODIFY id_scope bigint(21) NOT NULL AUTO_INCREMENT;

        CREATE TABLE {$this->config['jwt_table']} (
        client_id           VARCHAR(80)   NOT NULL,
        subject             VARCHAR(80),
        public_key          VARCHAR(2000) NOT NULL
        );

        CREATE TABLE {$this->config['jti_table']} (
        issuer              VARCHAR(80)   NOT NULL,
        subject             VARCHAR(80),
        audiance            VARCHAR(80),
        expires             TIMESTAMP     NOT NULL,
        jti                 VARCHAR(2000) NOT NULL
        );

        CREATE TABLE {$this->config['public_key_table']} (
        id_public_key int(21) NOT NULL,
        client_id varchar(80) NOT NULL,
        id_client int(21) NOT NULL,
        public_key varchar(4096) NOT NULL,
        private_key varchar(4096) NOT NULL,
        encryption_algorithm varchar(100) NOT NULL DEFAULT 'RS256'
        );
        ALTER TABLE {$this->config['public_key_table']}
        ADD PRIMARY KEY (id_public_key),
        ADD UNIQUE KEY client_idx (client_id),
        ADD UNIQUE KEY id_client (id_client);
        ALTER TABLE {$this->config['public_key_table']}
        MODIFY id_public_key int(21) NOT NULL AUTO_INCREMENT;
        ";

        return $sql;
    }
}