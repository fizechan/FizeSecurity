<?php

namespace fize\security;

/**
 * 跨站请求伪造处理
 */
class Csrf
{

    /**
     * @var string TOKEN 名称
     */
    protected static $name = '__token__';

    /**
     * 构造
     * @param string $name 指定 TOKEN 名称
     */
    public function __construct($name)
    {
        self::$name = $name;
    }

    /**
     * 取得表单 TOKEN
     * @return string
     */
    public static function token()
    {
        $token = md5($_SERVER['REQUEST_TIME_FLOAT']);
        $_SESSION[self::$name] = $token;
        return $token;
    }

    /**
     * 验证
     * @param string $token 待验证 TOKEN
     * @return bool
     */
    public static function check($token)
    {
        if (!isset($_SESSION[self::$name])) {
            return false;
        }
        if ($_SESSION[self::$name] === $token) {
            unset($_SESSION[self::$name]);
            return true;
        }
        unset($_SESSION[self::$name]);
        return false;
    }
}
