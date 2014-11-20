<?php
namespace Kizilare\Session;

Class Credentials
{
    const KEY = '4f43b5ade1afd';

    const LOGIN_COOKIE = 'credentials_cookie';

    protected $ttl = 7200;

    public function getCredentials()
    {
        $credentials = $this->getSession();
        if ( $credentials == false ) {
            throw new NoCredentialsException();
        }
        return $credentials;
    }

    public function storeCredentials( $username, $password )
    {
        $this->saveSession( $username, $password );
    }

    protected function saveSession( $username, $password )
    {
        $expire = time() + $this->ttl;
        $crypt_username = self::crypt( $username );
        $crypt_password = self::crypt( $password );
        return setcookie( self::LOGIN_COOKIE, "$crypt_username:$crypt_password", $expire, '/' );
    }

    protected function clearSession()
    {
        return setcookie( self::LOGIN_COOKIE, null, time() + 1, '/' );
    }

    protected function getSession()
    {
        if (empty( $_COOKIE[self::LOGIN_COOKIE] )) {
            return false;
        }
        list( $crypt_username, $crypt_password ) = explode( ':', $_COOKIE[self::LOGIN_COOKIE] );
        $username = self::deCrypt( $crypt_username );
        $password = self::deCrypt( $crypt_password );
        return array( $username, $password );
    }

    protected function crypt( $pass )
    {
        return base64_encode( mcrypt_encrypt( MCRYPT_RIJNDAEL_256, self::KEY, $pass, MCRYPT_MODE_ECB ) );
    }

    protected function deCrypt( $key )
    {
        return trim( mcrypt_decrypt( MCRYPT_RIJNDAEL_256, self::KEY, base64_decode( $key ), MCRYPT_MODE_ECB ) );
    }
}