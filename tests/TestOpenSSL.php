<?php

namespace app\controller;

use fize\security\OpenSSL;
use PHPUnit\Framework\TestCase;
use fize\crypt\Base64;

class TestOpenSSL extends TestCase
{

    public function testDigest()
    {
        $digest = OpenSSL::digest('这是一个很大很大的数据字符串', 'sha256');
        echo $digest;
    }

    public function testGetMdMethods()
    {
        $methods = OpenSSL::getMdMethods(true);
        var_dump($methods);
    }

    public function testCipherIvLength()
    {
        $result = OpenSSL::cipherIvLength('AES-128-CBC');
        var_dump($result);
    }

    public function testGetPublickey()
    {

    }

    public function testPublicEncrypt()
    {

    }

    public function testSetPublicKey()
    {

    }

    public function testCsrGetPublicKey()
    {
        $openssl = new OpenSSL();
        $openssl->setCsr(APP_ROOT . '/static/openssl/csr.pem');
        $public_key = $openssl->csrGetPublicKey();
        $openssl->setPkey($public_key);
        $info = $openssl->pkeyGetDetails();
        echo $info['key'];
    }

    public function testPkeyGetPublic()
    {
        $ca = file_get_contents(APP_ROOT . '/static/openssl/ca.crt');
        $public_key = OpenSSL::pkeyGetPublic($ca);

        $openssl = new OpenSSL();
        $openssl->setPublicKey($public_key);
        $openssl->pkeyExportToFile(APP_ROOT . '/static/openssl/ca_public.pem');
        echo 'OK';
    }

    public function testPkeyExportToFile()
    {

    }

    public function testGetCipherMethods()
    {
        $methods = OpenSSL::getCipherMethods();
        var_dump($methods);
    }

    public function testX509Fingerprint()
    {

    }

    public function testVerify()
    {
        $sign_base64 = 'nvtmiMyAZvilkXfQVmaziOvd4r1daVUQ0Md6UGF5YsrIF59QpKxez6sdOMSFHkkHZlFbrfRcwQwFwlRBPraqYHMIZzxTH37PTlKVpFvptg5VEzmVl3g/WzZixgfTeSIkfRqel76TcyTolZEcDtoiaN0hNXc1Z/rflQSr1DbrBDIN25Oqd61Ml0fn9tsDUPawMVwdTCrF6pqPIkrKyYgyYai3ySArAh62ERsDk1RC8E5RaLB7+LF8tNfxZtpaRR7CXOmWe6ab1mocV0aA4sNMaB1tfrfQvDMyBhAIPSs0p5w4+zEYQTd95q9eq6UTGsb6E5B67HWYOsz4K9WA+McHVQ==';
        $sign = Base64::decode($sign_base64);
        $openssl = new OpenSSL();
        $openssl->setPublicKey(APP_ROOT . '/static/openssl/pkey_4_public.pem');
        $data = '这个待签名字符串';
        $bool = $openssl->verify($data, $sign);
        var_dump($bool);
    }

    public function test__construct()
    {

    }

    public function testCsrExport()
    {
        $openssl = new OpenSSL();

        $subject = [
            "commonName" => "example2.com",
        ];
        $private_key = OpenSSL::pkeyNew([
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);

        $openssl->setPrivateKey($private_key);

        $csr = $openssl->csrNew($subject, ['digest_alg' => 'sha384'] );

        $openssl->setCsr($csr);
        $openssl->pkeyExportToFile(APP_ROOT . '/static/openssl/private2.key');
        $openssl->csrExportToFile(APP_ROOT . '/static/openssl/csr2.pem');
        $openssl->csrExport($str);
        echo $str;
    }

    public function testPkcs7Sign()
    {

    }

    public function testSpkiExportChallenge()
    {

    }

    public function testSetToPublicKeys()
    {

    }

    public function testSpki_verify()
    {

    }

    public function testPublicDecrypt()
    {

    }

    public function testX509CheckPrivateKey()
    {

    }

    public function testX509Checkpurpose()
    {

    }

    public function testDecrypt()
    {
        //$ciphertext64 = "gfcC6t1BarndpzMuvYj2JFpWHqlWSJMhTtxPN7QjyEg=";
        $key64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        $iv64="AAECAwQFBgcICQoLDA0ODw==";

        $key = base64_decode($key64, true);
        $iv = base64_decode($iv64, true);

        $openssl = new OpenSSL();
        $openssl->setKey($key);
        $encode = $openssl->encrypt('测试', 'aes-256-cbc', 0, $iv);
        echo $encode . '\r\n<br/>';

        $decode = $openssl->decrypt($encode, 'aes-256-cbc', 0, $iv);
        echo $decode . '\r\n<br/>';
    }

    public function testPkcs7Verify()
    {

    }

    public function testPkeyGetDetails()
    {

    }

    public function testOpen()
    {
        //@todo AES256方法解密出来的结果前面有丢失字符串

        //密封
        $public_keys = [file_get_contents(APP_ROOT . '/static/openssl/pkey_1_public.pem')];
        $data = "12345678910ABCDEFGABCDEFGABCDEFGABCDEFG这是待加密字符串。ABCDEFG";
        //$data = Base64::encode($data);
        var_dump($data);
        $iv1 = OpenSSL::randomPseudoBytes(OpenSSL::cipherIvLength('AES256'));
        $ekeys = [];

        $openssl = new OpenSSL();
        $openssl->setToPublicKeys($public_keys);
        $openssl->seal($data, $sealed, $ekeys, 'AES256', $iv1);
        var_dump($sealed);
        var_dump($ekeys);

        echo Base64::encode($sealed);  //可视字符串

        //解封
        $iv2 = OpenSSL::randomPseudoBytes(OpenSSL::cipherIvLength('AES256'));
        $openssl->setPrivateKey(APP_ROOT . '/static/openssl/pkey_1_private.pem', true);
        $openssl->open($sealed, $open_data, $ekeys[0], 'AES256', $iv2);
        var_dump($open_data);
    }

    public function testX509Export()
    {

    }

    public function testSetPrivateKey()
    {

    }

    public function testFreeKey()
    {
        $pkey = OpenSSL::pkeyNew();
        var_dump($pkey);
        OpenSSL::freeKey($pkey);
        var_dump($pkey);
    }

    public function testPkeyGetPrivate()
    {

    }

    public function testPkeyFree()
    {

    }

    public function testX509ExportToFile()
    {

    }

    public function testPbkdf2()
    {
        $string = OpenSSL::pbkdf2('123456', OpenSSL::randomPseudoBytes(64), 12, 10000);
        $string = Base64::encode($string);
        var_dump($string);
    }

    public function testPrivateDecrypt()
    {
        $data = '这个待加密字符串';

        //公钥加密
        $openssl = new OpenSSL();
        $openssl->setPublicKey(APP_ROOT . '/static/openssl/pkey_4_public.pem');
        $encrypt = $openssl->publicEncrypt($data);
        var_dump($encrypt);

        //私钥解密
        $openssl->setPrivateKey(APP_ROOT . '/static/openssl/pkey_4_private.pem', true, '123456');
        $decrypt = $openssl->privateDecrypt($encrypt);
        var_dump($decrypt);
    }

    public function testSetPkey()
    {

    }

    public function testCsrNew()
    {
        $openssl = new OpenSSL();

        $subject = [
            "commonName" => "example3.com",
        ];
        $private_key = OpenSSL::pkeyNew([
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);

        $openssl->setPrivateKey($private_key);

        $csr = $openssl->csrNew($subject, ['digest_alg' => 'sha384'] );

        $openssl->setCsr($csr);
        $openssl->pkeyExportToFile(APP_ROOT . '/static/openssl/private3.key');
        $openssl->csrExportToFile(APP_ROOT . '/static/openssl/csr3.pem');
        echo 'OK';
    }

    public function testPkcs7Encrypt()
    {

    }

    public function testSetKey()
    {

    }

    public function testPkcs7Read()
    {

    }

    public function testSpki_new()
    {

    }

    public function testPkcs12ExportToFile()
    {
        $openssl = new OpenSSL();
        $openssl->setX509(APP_ROOT . '/static/openssl/ca.crt');
        $openssl->setPrivateKey(APP_ROOT . '/static/openssl/ca_private.key', true, '123456');
        $openssl->pkcs12ExportToFile(APP_ROOT . '/static/openssl/ca.pkcs12', '12345678');
        echo 'OK';
    }

    public function testSign()
    {
        $openssl = new OpenSSL();
        $openssl->setPrivateKey(APP_ROOT . '/static/openssl/pkey_4_private.pem', true, '123456');
        $data = '这个待签名字符串';
        $sign = $openssl->sign($data);
        //echo $sign;
        $sign_base64 = Base64::encode($sign);
        echo $sign_base64;
    }

    public function testPkeyNew()
    {
        $pkey = OpenSSL::pkeyNew();
        $openssl = new OpenSSL();
        $openssl->setPkey($pkey);
        $openssl->pkeyExportToFile(APP_ROOT . '/static/openssl/pkey_2.pem');

        $pkey = OpenSSL::pkeyNew();
        $openssl = new OpenSSL();
        $openssl->setPkey($pkey);
        $openssl->pkeyExportToFile(APP_ROOT . '/static/openssl/pkey_4_private.pem');

        $pkey = file_get_contents(APP_ROOT . '/static/openssl/pkey_4_private.pem');

        $private_key = OpenSSL::pkeyGetPrivate($pkey);
        var_dump($private_key);

        $public_key = OpenSSL::pkeyGetPublic($pkey, true);
        var_dump($public_key);

        $openssl = new OpenSSL();
        $openssl->setPkey($public_key);
        $details = $openssl->pkeyGetDetails();
        var_dump($details);
        file_put_contents(APP_ROOT . '/static/openssl/pkey_4_public.pem', $details['key']);

        $errmsg = OpenSSL::errorString();
        echo $errmsg;
    }

    public function testSetCsr()
    {

    }

    public function testCsrGetSubject()
    {
        $openssl = new OpenSSL();
        $openssl->setCsr(APP_ROOT . '/static/openssl/csr.pem');
        $subject = $openssl->csrGetSubject();
        var_dump($subject);
    }

    public function testX509Parse()
    {

    }

    public function testSeal()
    {

    }

    public function testGetCertLocations()
    {
        $lcts = OpenSSL::getCertLocations();
        var_dump($lcts);
    }

    public function test__destruct()
    {

    }

    public function testPkcs12Export()
    {
        $openssl = new OpenSSL();
        $openssl->setX509(APP_ROOT . '/static/openssl/ca.crt');
        $openssl->setPrivateKey(APP_ROOT . '/static/openssl/ca_private.key', true, '123456');
        $openssl->pkcs12Export($out, '12345678');
        echo $out;
    }

    public function testErrorString()
    {
        $key64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        $iv64="AAECAwQFBgcICQoLDA0ODw==";

        $key = base64_decode($key64, true);
        $iv = base64_decode($iv64, true);

        $openssl = new OpenSSL();
        $openssl->setKey($key);
        $encode = $openssl->encrypt('测试', 'aes-256-cbc', 0, $iv);

        $decode = $openssl->decrypt($encode . 'error_str', 'aes-256-cbc', 0, $iv);
        var_dump($decode);

        $errmsg = OpenSSL::errorString();
        echo $errmsg;
    }

    public function testPkcs12Read()
    {
        $content = file_get_contents(APP_ROOT . '/static/openssl/ca.pkcs12');
        OpenSSL::pkcs12Read($content, $certs, '12345678');
        var_dump($certs);
    }

    public function testX509Free()
    {

    }

    public function testPkeyExport()
    {

    }

    public function testPrivateEncrypt()
    {
        $data = '这个待加密字符串';
        $openssl = new OpenSSL();

        //私钥加密
        $openssl->setPrivateKey(APP_ROOT . '/static/openssl/pkey_4_private.pem', true, '123456');
        $encrypt = $openssl->privateEncrypt($data);
        var_dump($encrypt);

        //公钥解密
        $openssl->setPublicKey(APP_ROOT . '/static/openssl/pkey_4_public.pem');
        $decrypt = $openssl->publicDecrypt($encrypt);
        var_dump($decrypt);
    }

    public function testSpkiExport()
    {

    }

    public function testSetX509()
    {

    }

    public function testGetCurveNames()
    {
        $names = OpenSSL::getCurveNames();
        var_dump($names);
    }

    public function testRandomPseudoBytes()
    {

    }

    public function testX509Read()
    {

    }

    public function testGetPrivatekey()
    {

    }

    public function testCsrSign()
    {
        $openssl = new OpenSSL();
        $openssl->setCsr(APP_ROOT . '/static/openssl/csr3.pem');
        $openssl->setX509(APP_ROOT . '/static/openssl/ca.crt');
        $openssl->setPrivateKey(APP_ROOT . '/static/openssl/ca_private.key', true, '123456');

        $crt = $openssl->csrSign(365, ['digest_alg'=>'sha256']);
        $openssl->setX509($crt);
        $openssl->x509ExportToFile(APP_ROOT . '/static/openssl/ca2.crt');
        echo 'OK';
    }

    public function testPkcs7Decrypt()
    {

    }

    public function testEncrypt()
    {
        $key64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
        $iv64="AAECAwQFBgcICQoLDA0ODw==";

        $key = base64_decode($key64, true);
        $iv = base64_decode($iv64, true);

        var_dump($key64);
        var_dump($iv64);
        var_dump($key);
        var_dump($iv);

        $openssl = new OpenSSL();
        $openssl->setKey($key);
        $encode = $openssl->encrypt('测试', 'aes-256-cbc', 0, $iv);
        echo $encode . '\r\n<br/>';

        $decode = $openssl->decrypt($encode, 'aes-256-cbc', 0, $iv);
        echo $decode . '\r\n<br/>';

        self::assertEquals($decode, '测试');

        $openssl2 = new OpenSSL();
        $openssl2->setKey('123456');
        $encode2 = $openssl2->encrypt('测试', 'aes-256-cbc', 0, $iv);
        $decode2 = $openssl2->decrypt($encode2, 'aes-256-cbc', 0, $iv);
        self::assertEquals($decode2, '测试');
    }

    public function testDhComputeKey()
    {
        //todo 待测试
    }

    public function testCsrExportToFile()
    {
        $openssl = new OpenSSL();

        $subject = [
            "commonName" => "example.com",
        ];
        $private_key = OpenSSL::pkeyNew([
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ]);

        $openssl->setPrivateKey($private_key);

        $csr = $openssl->csrNew($subject, ['digest_alg' => 'sha384'] );

        $openssl->setCsr($csr);
        $openssl->pkeyExportToFile(APP_ROOT . '/static/openssl/private.key');
        $openssl->csrExportToFile(APP_ROOT . '/static/openssl/csr.pem', false);

        echo 'OK';
    }
}
