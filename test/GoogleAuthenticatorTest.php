<?php

namespace app\controller;

use fize\security\GoogleAuthenticator;
use PHPUnit\Framework\TestCase;

class GoogleAuthenticatorTest extends TestCase
{

    public function testGetCode()
    {
        $auth = new GoogleAuthenticator();

        $secret = $auth->createSecret();
        var_dump($secret);
        //B3ULJDCR4NJ2HPXX
        $secret = 'B3ULJDCR4NJ2HPXX';
        $code = $auth->getCode($secret);
        var_dump($code);

        $result = $auth->verifyCode($secret, $code);
        var_dump($result);
    }

    public function testCreateSecret()
    {
        $auth = new GoogleAuthenticator();

        $secret = $auth->createSecret();
        var_dump($secret);
        //B3ULJDCR4NJ2HPXX
        $secret = 'B3ULJDCR4NJ2HPXX';
        $code = $auth->getCode($secret);
        var_dump($code);

        $result = $auth->verifyCode($secret, $code);
        var_dump($result);
    }

    public function testSetCodeLength()
    {
        $auth = new GoogleAuthenticator();

        $secret = $auth->createSecret();
        var_dump($secret);
        //B3ULJDCR4NJ2HPXX
        $secret = 'B3ULJDCR4NJ2HPXX';
        $code = $auth->getCode($secret);
        var_dump($code);

        $result = $auth->verifyCode($secret, $code);
        var_dump($result);
    }

    public function testVerifyCode()
    {
        $auth = new GoogleAuthenticator();

        $secret = $auth->createSecret();
        var_dump($secret);
        //B3ULJDCR4NJ2HPXX
        $secret = 'B3ULJDCR4NJ2HPXX';
        $code = $auth->getCode($secret);
        var_dump($code);

        $result = $auth->verifyCode($secret, $code);
        var_dump($result);
    }

    public function testGetQRCodeGoogleUrl()
    {
        $auth = new GoogleAuthenticator();

        $secret = $auth->createSecret();
        var_dump($secret);
        //B3ULJDCR4NJ2HPXX
        $secret = 'B3ULJDCR4NJ2HPXX';
        $code = $auth->getCode($secret);
        var_dump($code);

        $result = $auth->verifyCode($secret, $code);
        var_dump($result);
    }
}
