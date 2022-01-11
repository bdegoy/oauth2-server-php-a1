<?php
/* 
OAuthSD project
OAuthSD OpenID Connect server by DnC, version 2.

This code is not an open source!
You can not access, dispose, modify, transmit etc. this code without the written permission of DnC.
You can only use one coded copy provided you have a particular license from DnC.
Auteur : Bertrand Degoy 
Copyright (c) 2016-2021 Bertrand degoy  
All rights reserved
*/

//[dnc102]

namespace OAuth2\Encryption;

use Exception;
use InvalidArgumentException;

/**
* @author B.Degoy https://degoy.com
* d'après Nov Matake https://github.com/nov/jose-php
*/
class Jwe implements EncryptionInterface {

    var $content; // or 'plaintext'
    var $raw;
    var $cipher_text;
    
    /**
    * urlSafeB64Decode de la clé cryptée passée par le JWT si le Mode de gestion de clé CEK est autre que 'dir'
    * 
    * @var mixed
    */
    var $jwe_encrypted_cek;
    
    /**
    * Content Encryption Key (CEK).
    * En encodage du JWE, la valeur est définie par la fonction encryptContentEncryptionKey.
    * En décodage du JWE la valeur est définie par la fonction decryptContentEncryptionKey :
    * Si le Mode de gestion de clé est Cryptage Direct, la valeur $key est prise dans l'appel de la méthode decode ou peut avoir été passée par la méthode setCEK. 
    * Sinon, la fonction décripte $key en fonction de l'algorithme passé dans le header.   
    * 
    * @var mixed
    */
    private $content_encryption_key;
    
    /**
    * Première moitié de la CEK 
    * Doit uniquement être déduite de content_encryption_key par la méthode deriveEncryptionAndMacKeys()
    *          
    * @var mixed
    */
    private $mac_key;
    
    /**
    * passphrase pour openssl_encrypt().
    * Deuxième moitié de la CEK 
    * Doit uniquement être déduite de content_encryption_key par la méthode deriveEncryptionAndMacKeys()
    *          
    * @var mixed
    */
    private $encryption_key;
               
    var $iv;
    var $authentication_tag;
    var $auth_data;

    /**
    * @param mixed $payload
    * @param mixed $key
    * @param mixed $algorithm
    * @param mixed $encryption_method
    */
    public function encode($payload, $key, $algorithm = 'RSA1_5', $encryption_method = 'A128CBC-HS256')
    {
        if ($payload instanceof Jwt) {  
            // payload is Jwt, make it string.
            $this->raw = $payload->toString();
        } else {
            // if not Jwt, payload should be string
            $this->raw = $payload;
        }

        $this->header['alg'] = $algorithm;
        $this->header['enc'] = $encryption_method;

        //TODO: generate header['kid']  see https://github.com/nov/jose-php/blob/master/src/JOSE/JWE.php

        $this->content = $this->raw;
        $this->generateContentEncryptionKey($key);
        $this->encryptContentEncryptionKey($key);
        $this->generateIv();
        $this->deriveEncryptionAndMacKeys();
        $this->encryptCipherText();
        $this->generateAuthenticationTag();

        $segments = array(
            $this->urlSafeB64Encode(json_encode($header)),
            $this->urlSafeB64Encode($encrypted_key),
            $this->urlSafeB64Encode($initialization_vector),
            $this->urlSafeB64Encode($this->encrypt($payload)),
            $this->urlSafeB64Encode($authentication_tag)
        );

        return implode('.', $segments);
    }

    /**
    * @param string      $jwe
    * @param null        $key
    * @param array|bool  $allowedAlgorithms
    * @return bool|mixed
    */
    public function decode($jwe, $key, $allowedAlgorithms = true)
    {
        //DebugBreak("435347910947900005@127.0.0.1;d=1");  //DEBUG
        
        if (!strpos($jwe, '.')) {
            return false;
        }

        $segments = explode('.', $jwe);

        if (count($segments) != (5)) {
            return false;
        }

        // decode and check

        list($headb64, $enckey64, $iv64, $payloadb64, $authag64 ) = $segments;

        if (null === ($this->header = json_decode($this->urlSafeB64Decode($headb64), true))) {
            return false;
        }

        $alg = $this->header['alg'];
        if ( $alg == 'dir' ) {
            // Mode de gestion de clé CEK = Cryptage Direct : la clé est transmise hors ligne, non cryptée et doit être fournie dans l'appel de la méthode.
            $this->jwe_encrypted_cek = $key;
            if ( null === ($this->jwe_encrypted_cek) )
                return false;  

        } else {
            // La clé CEK est passée par le JWE sous forme cryptée
            if ( null === ($this->jwe_encrypted_cek = $this->urlSafeB64Decode($enckey64)))
                return false;
        }

        if (null === ($this->iv = $this->urlSafeB64Decode($iv64)))
            return false;

        if (null === ($this->cipher_text = $this->urlSafeB64Decode($payloadb64)))
            return false;

        if (null === ($this->authentication_tag = $this->urlSafeB64Decode($authag64)))
            return false;

        if ((bool) $allowedAlgorithms) {
            if (!isset($header['alg']))
                return false;

            // check if bool arg supplied here to maintain BC
            if (is_array($allowedAlgorithms) && !in_array($header['alg'], $allowedAlgorithms))
                return false;

        }

        // decrypt CipherText and authenticate
        $this->decryptContentEncryptionKey($key);
        $this->deriveEncryptionAndMacKeys();
        if ( $this->checkAuthenticationTag() ) {
            $content_encoding_method = $this->TranslateJei2OpenSSL($this->header['enc']);
            if ( ! $this->decryptCipherText($content_encoding_method) ) 
            return false;
        } else {
            return false;
        }

        // Return JWE payload
        //return $this->content;
        return trim($this->content, "\x00..\x1F");       // delete trailing invisible chars
    }


    ////////////

    protected function extract($segment, $as_binary = false) {
        $stringified = JOSE_URLSafeBase64::decode($segment);
        if ($as_binary) {
            $extracted = $stringified;
        } else {
            $extracted = json_decode($stringified);
            if ($stringified !== 'null' && $extracted === null) {
                throw new JOSE_Exception_InvalidFormat('Compact de-serialization failed');
            }
        }
        return $extracted;
    }

    protected function TranslateJei2OpenSSL( $jwe_enc_identifier ) {
        // Translate JWE enc identifier to corresponding openssl cipher methods
        switch ( $jwe_enc_identifier ) {
            // Content encryption class AES/GCM
            case 'A128GCM': return "aes-128-gcm";         // not used by Nimbus ?
            case 'A192GCM': return "aes-192-gcm";
            case 'A256GCM': return "aes-256-gcm";
                // Content encryption class AES/CBC/HMAC/SHA
            case 'A128CBC-HS256': return "AES-128-CBC";   // AES mode CBC, cipher avec AES-128 et hash_hmac avec sha256
            case 'A192CBC-HS384': return "AES-128-CBC";
            case 'A256CBC-HS512': return "AES-256-CBC";
            default :
                throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
        }
    }



    ////////////

    function encrypt($key, $algorithm = 'RSA1_5', $encryption_method = 'A128CBC-HS256') {
        $this->header['alg'] = $algorithm;
        $this->header['enc'] = $encryption_method;

        //TODO: set header['kid']

        $this->content = $this->raw;
        $this->generateContentEncryptionKey($key);
        $this->encryptContentEncryptionKey($key);
        $this->generateIv();
        $this->deriveEncryptionAndMacKeys();
        $this->encryptCipherText();
        $this->generateAuthenticationTag();
        return $this;
    }



    ////////////



    /*
    private function cipher() {

        switch ($this->header['enc']) {
        case 'A128GCM':     
        case 'A256GCM':
            throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
        case 'A128CBC-HS256':
        case 'A256CBC-HS512':
            $cipher = new AES(AES::MODE_CBC);                      //***** AES
            break;
        default:
            throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
        switch ($this->header['enc']) {
        case 'A128GCM':
        case 'A128CBC-HS256':
            $cipher->setBlockLength(128);
            break;
        case 'A256GCM':
        case 'A256CBC-HS512':
            $cipher->setBlockLength(256);
            break;
        default:
            throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
        return $cipher;
    } */

    private function generateRandomBytes($length) {
        return Random::string($length);
    }

    private function generateIv() {
        switch ($this->header['enc']) {
            case 'A128GCM':
            case 'A128CBC-HS256':
                $this->iv = $this->generateRandomBytes(128 / 8);
                break;
            case 'A256GCM':
            case 'A256CBC-HS512':
                $this->iv = $this->generateRandomBytes(256 / 8);
                break;
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
    }

    private function generateContentEncryptionKey($key) {
        if ($this->header['alg'] == 'dir') {
            $this->content_encryption_key = $key;
        } else {
            switch ($this->header['enc']) {
                case 'A128GCM':
                case 'A128CBC-HS256':
                    $this->content_encryption_key = $this->generateRandomBytes(256 / 8);
                    break;
                case 'A256GCM':
                case 'A256CBC-HS512':
                    $this->content_encryption_key = $this->generateRandomBytes(512 / 8);
                    break;
                default:
                    throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
            }
        }
    }

    private function encryptContentEncryptionKey($key) {
        switch ($this->header['alg']) {
            case 'RSA1_5':                                                             
                $rsa = $this->rsa($key, RSA::ENCRYPTION_PKCS1);                             
                $this->jwe_encrypted_cek = $rsa->encrypt($this->content_encryption_key);    
                break;
            case 'RSA-OAEP':
                $rsa = $this->rsa($key, RSA::ENCRYPTION_OAEP);             
                $this->jwe_encrypted_cek = $rsa->encrypt($this->content_encryption_key);   
                break;
            case 'dir':
                $this->jwe_encrypted_cek = '';
                return;
            case 'A128KW':
            case 'A256KW':
            case 'ECDH-ES':
            case 'ECDH-ES+A128KW':
            case 'ECDH-ES+A256KW':
                throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
        if (!$this->jwe_encrypted_cek) {
            throw new JOSE_Exception_EncryptionFailed('Master key encryption failed');
        }
    }

    /**
    * En décodage du JWE, définit content_encryption_key.
    * Si le Mode de gestion de clé est Cryptage Direct, la valeur $key est prise tele quelle. 
    * Sinon, la fonction décripte $key en fonction de l'algorithme passé dans le header.   
    * 
    * @param mixed $key
    */
    private function decryptContentEncryptionKey($key) {
        $this->generateContentEncryptionKey(null); # NOTE: run this always not to make timing difference
        $fake_content_encryption_key = $this->content_encryption_key;
        switch ($this->header['alg']) {
            case 'RSA1_5':
                $rsa = $this->rsa($key, RSA::ENCRYPTION_PKCS1);   
                $this->content_encryption_key = $rsa->decrypt($this->jwe_encrypted_cek);
                break;
            case 'RSA-OAEP':
                $rsa = $this->rsa($key, RSA::ENCRYPTION_OAEP);    
                $this->content_encryption_key = $rsa->decrypt($this->jwe_encrypted_cek);
                break;
            case 'dir':
                $this->content_encryption_key = $key;
                break;
            case 'A128KW':
            case 'A256KW':
            case 'ECDH-ES':
            case 'ECDH-ES+A128KW':
            case 'ECDH-ES+A256KW':
                throw new JOSE_Exception_UnexpectedAlgorithm('Algorithm not supported');
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
        if (!$this->content_encryption_key) {
            # NOTE:
            #  Not to disclose timing difference between CEK decryption error and others.
            #  Mitigating Bleichenbacher Attack on PKCS#1 v1.5
            #  ref.) http://inaz2.hatenablog.com/entry/2016/01/26/222303
            $this->content_encryption_key = $fake_content_encryption_key;
        }
    }

    private function deriveEncryptionAndMacKeys() {
        switch ($this->header['enc']) {                 
            case 'A128GCM':
            case 'A256GCM':
                $this->encryption_key = $this->content_encryption_key;
                $this->mac_key = "won't be used";
                break;
            case 'A128CBC-HS256':
                $this->deriveEncryptionAndMacKeysCBC(256);
                break;
            case 'A256CBC-HS512':
                $this->deriveEncryptionAndMacKeysCBC(512);
                break;
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
        if ( empty($this->encryption_key) || empty($this->mac_key)) {
            throw new JOSE_Exception_DecryptionFailed('Encryption/Mac key derivation failed');
        }
    }

    private function deriveEncryptionAndMacKeysCBC($sha_size) {
        $this->mac_key = substr($this->content_encryption_key, 0, $sha_size / 2 / 8);
        $this->encryption_key = substr($this->content_encryption_key, $sha_size / 2 / 8);
    }


    private function encryptCipherText($plaintext, $cipher) {

        // @see https://www.php.net/manual/fr/function.openssl-encrypt.php

        $ivlen = openssl_cipher_iv_length($cipher);
        $iv = openssl_random_pseudo_bytes($ivlen);
        $this->cipher_text = openssl_encrypt(
            $plaintext, 
            $cipher, 
            $this->encryption_key,              // passphrase 
            OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING,  // options 
            $iv, 
            $tag);

    }

    private function decryptCipherText($cipher) {

        //@see https://www.php.net/manual/fr/function.openssl-decrypt.php

        try {
            $this->content = openssl_decrypt(
                $this->cipher_text,                 // data
                $cipher,                            // cypher_algo 
                $this->encryption_key,              // passphrase 
                OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING,  // options 
                $this->iv                           // iv
            );
        } catch(Exception $e) {
            // log ???
            return false;    
        }
        if ( ! ((bool)$this->content) ) {
            // log ???
            return false;    
        } 
        return $this->content;

    }

    private function generateAuthenticationTag() {
        $this->authentication_tag = $this->calculateAuthenticationTag();
    }

    private function calculateAuthenticationTag($use_raw = false) {     //TODO: $use_raw ???
        switch ($this->header['enc']) {
            case 'A128GCM':
            case 'A256GCM':
                return $this->calculateAuthenticationTagGCM();     // Ne pas utiliser, bug!
            case 'A128CBC-HS256':
                return $this->calculateAuthenticationTagCBC(256);
            case 'A256CBC-HS512':
                return $this->calculateAuthenticationTagCBC(512);
            default:
                throw new JOSE_Exception_UnexpectedAlgorithm('Unknown algorithm');
        }
    }

    private function calculateAuthenticationTagGCM() {    //TODO: à vérifier et tester

        if (!$this->auth_data) {
            $this->auth_data = $this->compact((object) $this->header);
        }

        $auth_data_length = strlen($this->auth_data);

        $secured_input = implode('', array(
            $this->auth_data,
            $this->iv,
            $this->cipher_text,
            // NOTE: PHP doesn't support 64bit big endian, so handling upper & lower 32bit.
            pack('N2', ($auth_data_length / $max_32bit) * 8, ($auth_data_length % $max_32bit) * 8)
        )); 

        return substr(
            hash_hmac('sha' . $sha_size, $secured_input, $this->mac_key, true),
            0, $sha_size / 2 / 8
        );
    }

    private function calculateAuthenticationTagCBC($sha_size) {

        if (!$this->auth_data) {
            $this->auth_data = $this->compact((object) $this->header);
        }

        $auth_data_length = strlen($this->auth_data);
        $max_32bit = 2147483647;
        $secured_input = implode('', array(
            $this->auth_data,
            $this->iv,
            $this->cipher_text,
            // NOTE: PHP doesn't support 64bit big endian, so handling upper & lower 32bit.
            pack('N2', ($auth_data_length / $max_32bit) * 8, ($auth_data_length % $max_32bit) * 8)
        ));

        return substr(
            hash_hmac('sha' . $sha_size, $secured_input, $this->mac_key, true),
            0, $sha_size / 2 / 8
        );
    }
    

    private function checkAuthenticationTag() {
        if (hash_equals($this->authentication_tag, $this->calculateAuthenticationTag())) {
            return true;
        } else {
            //throw new JOSE_Exception_UnexpectedAlgorithm('Invalid authentication tag');
            return false;
        }
    }

    //////////

    /**
    * @param string $data
    * @return string
    */
    public function urlSafeB64Encode($data)
    {
        $b64 = base64_encode($data);
        $b64 = str_replace(
            array('+', '/', "\r", "\n", '='),
            array('-', '_'),
            $b64);

        return $b64;
    }

    /**
    * @param string $b64
    * @return mixed|string
    */
    public function urlSafeB64Decode($b64)
    {
        //*
        $remainder = strlen($b64) % 4;
        if ($remainder) {
            $padlen = 4 - $remainder;
            $b64 .= str_repeat('=', $padlen);
        } //*/

        $b64 = str_replace(
            array('-', '_'),
            array('+', '/'),
            $b64);

        return base64_decode($b64);
    }

    public function hexToStr($hex){
        $string='';
        for ($i=0; $i < strlen($hex)-1; $i+=2){
            $string .= chr(hexdec($hex[$i].$hex[$i+1]));
        }
        return $string;
    }   

    public function compact($segment) {
        if (is_object($segment)) {
            $stringified = str_replace("\/", "/", json_encode($segment));
        } else {
            $stringified = $segment;
        }
        if ($stringified === 'null' && $segment !== null) { // shouldn't happen, just for safe
            throw new JOSE_Exception_InvalidFormat('Compact seriarization failed');
        }
        return $this->urlSafeB64Encode($stringified);
    }


}