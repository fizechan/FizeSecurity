<?php

namespace Fize\Security;

/**
 * 非标准RSA
 *
 * 经常在对接JAVA编写的接口时，对方使用非标准RSA而导致各种问题，使用本类方法可以快速解决。
 */
class SpecialRSA
{

    /**
     * 由于提供的密钥为非PKCS8标准格式，提供本方法进行转换
     * @param string      $privateKey 私钥
     * @param string|null $saveFile   保存文件
     * @return string
     */
    public static function toPKCS8PrivateKeyFile(string $privateKey, string $saveFile = null): string
    {
        $str = $privateKey;
        $search = ['*', '-'];
        $replace = ['+', '/'];
        $str = str_replace($search, $replace, $str);
        $str = chunk_split($str, 64, "\n");
        $str = "-----BEGIN RSA PRIVATE KEY-----\n$str-----END RSA PRIVATE KEY-----\n";
        if ($saveFile) {
            file_put_contents($saveFile, $str);
        }
        return $str;
    }

    /**
     * 生成PKCS1密钥，使用安装OpenSSL
     * @param string $pkcs8File 原先的PKCS8密钥文件
     * @param string $pkcs1File 要生成的PKCS1密钥文件
     * @return string 返回命令输出结果
     */
    public static function toPKCS1PrivateKeyFile(string $pkcs8File, string $pkcs1File): string
    {
        $command = "openssl rsa -in $pkcs8File -out $pkcs1File";
        exec($command, $output);
        return $output;
    }

    /**
     * 由于提供的公钥为非标准格式，提供本方法进行转换
     * @param string      $publicKey 公钥
     * @param string|null $saveFile  保存文件
     * @return string
     */
    public static function toPublicKeyFile(string $publicKey, string $saveFile = null): string
    {
        $str = $publicKey;
        $search = ['*', '-'];
        $replace = ['+', '/'];
        $str = str_replace($search, $replace, $str);
        $str = chunk_split($str, 64, "\n");
        $str = "-----BEGIN PUBLIC KEY-----\n$str-----END PUBLIC KEY-----\n";
        if ($saveFile) {
            file_put_contents($saveFile, $str);
        }
        return $str;
    }

    /**
     * 公钥加密
     * @param string $data          要加密的字符串
     * @param string $publicKeyFile 公钥文件路径
     * @return string 加密字符串
     */
    public static function publicEncrypt(string $data, string $publicKeyFile): string
    {
        $publicKey = openssl_pkey_get_public(file_get_contents($publicKeyFile));
        $crypto = '';
        foreach (str_split($data, 117) as $chunk) {
            openssl_public_encrypt($chunk, $encrypted, $publicKey);
            $crypto .= $encrypted;
        }
        $crypto = base64_encode($crypto);
        return $crypto;
    }

    /**
     * 私钥解密
     * @param string $data           要解密的字符串
     * @param string $privateKeyFile 私钥文件路径
     * @return string 加密字符串
     */
    public static function privateDecrypt(string $data, string $privateKeyFile): string
    {
        $privateKey = openssl_pkey_get_private(file_get_contents($privateKeyFile));
        $data = base64_decode($data);
        $crypto = '';
        foreach (str_split($data, 128) as $chunk) {
            openssl_private_decrypt($chunk, $decrypted, $privateKey);
            $crypto .= $decrypted;
        }
        return $crypto;
    }

    /**
     * 私钥签名
     * @param string $data           要签名的字符串
     * @param string $privateKeyFile 私钥文件路径
     * @return string 签名
     */
    public static function privateSign(string $data, string $privateKeyFile): string
    {
        $privateKey = openssl_pkey_get_private(file_get_contents($privateKeyFile));
        openssl_sign($data, $sign, $privateKey);
        $sign = base64_encode($sign);
        $sign = str_replace(['+', '/'], ['*', '-'], $sign);  // 特别转义
        return $sign;
    }

    /**
     * 公钥验签
     * @param string $data          要验签的字符串
     * @param string $sign          签名
     * @param string $publicKeyFile 公钥文件路径
     * @return int 如果签名正确返回 1, 签名错误返回 0, 内部发生错误则返回-1.
     */
    public static function publicVerify(string $data, string $sign, string $publicKeyFile): int
    {
        $publicKey = openssl_pkey_get_public(file_get_contents($publicKeyFile));
        $sign = str_replace(['*', '-'], ['+', '/'], $sign);  // 特别转义
        $sign = base64_decode($sign);
        return openssl_verify($data, $sign, $publicKey);
    }

}