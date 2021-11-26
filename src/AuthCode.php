<?php

namespace Fize\Security;

/**
 *  Discuz!自定义的一个加解密算法
 */
class AuthCode
{

    /**
     * 禁止实例化
     */
    private function __construct()
    {
    }

    /**
     * 加密、解密方法
     * @param string $string    原文或者密文
     * @param string $operation 操作(ENCODE | DECODE), 默认为 DECODE
     * @param string $key       密钥
     * @param int    $expiry    密文有效期, 加密时候有效， 单位 秒，0 为永久有效
     * @return string 处理后的 原文或者 经过 base64_encode 处理后的密文
     * @example
     *                          $a = authcode('abc', 'ENCODE', 'key');
     *                          $b = authcode($a, 'DECODE', 'key');  // $b(abc)
     *                          $a = authcode('abc', 'ENCODE', 'key', 3600);
     *                          $b = authcode('abc', 'DECODE', 'key'); // 在一个小时内，$b(abc)，否则 $b 为空
     */
    private static function authcode($string, $operation = 'DECODE', $key = '', $expiry = 0)
    {
        $ckey_length = 4;
        if (!$key) {
            $key = $_SERVER['HTTP_USER_AGENT'];
        }
        $keya = md5(substr($key, 0, 16));
        $keyb = md5(substr($key, 16, 16));
        $keyc = $ckey_length ? ($operation == 'DECODE' ? substr($string, 0, $ckey_length) : substr(md5(microtime()), -$ckey_length)) : '';

        $cryptkey = $keya . md5($keya . $keyc);
        $key_length = strlen($cryptkey);

        $string = $operation == 'DECODE' ? base64_decode(substr($string, $ckey_length)) : sprintf('%010d', $expiry ? $expiry + time() : 0) . substr(md5($string . $keyb), 0, 16) . $string;
        $string_length = strlen($string);

        $result = '';
        $box = range(0, 255);

        $rndkey = [];
        for ($i = 0; $i <= 255; $i++) {
            $rndkey[$i] = ord($cryptkey[$i % $key_length]);
        }

        for ($j = $i = 0; $i < 256; $i++) {
            $j = ($j + $box[$i] + $rndkey[$i]) % 256;
            $tmp = $box[$i];
            $box[$i] = $box[$j];
            $box[$j] = $tmp;
        }

        for ($a = $j = $i = 0; $i < $string_length; $i++) {
            $a = ($a + 1) % 256;
            $j = ($j + $box[$a]) % 256;
            $tmp = $box[$a];
            $box[$a] = $box[$j];
            $box[$j] = $tmp;
            $result .= chr(ord($string[$i]) ^ ($box[($box[$a] + $box[$j]) % 256]));
        }

        if ($operation == 'DECODE') {
            if ((substr($result, 0, 10) == 0 || intval(substr($result, 0, 10)) - intval(time()) > 0) && substr($result, 10, 16) == substr(md5(substr($result, 26) . $keyb), 0, 16)) {
                return substr($result, 26);
            } else {
                return false; //解码失败返回false
            }
        } else {
            return $keyc . str_replace('=', '', base64_encode($result));
        }
    }

    /**
     * 加密字符串
     * @param string $string 原文
     * @param string $key    密钥
     * @param int    $expiry 密文有效期。单位 秒，0 为永久有效
     * @return string
     */
    public static function encode($string, $key = '', $expiry = 0)
    {
        return self::authcode($string, 'ENCODE', $key, $expiry);
    }

    /**
     * 解密字符串得到原字符串
     * @param string $string 已加密字符串
     * @param string $key    密钥
     * @return string
     */
    public static function decode($string, $key = '')
    {
        return self::authcode($string, 'DECODE', $key);
    }
}
