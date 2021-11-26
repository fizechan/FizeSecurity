<?php

namespace Fize\Security;

/**
 * 密码散列算法
 */
class Password
{

    /**
     * 返回指定散列（hash）的相关信息
     * @param string $hash 指定散列
     * @return array
     */
    public static function getInfo($hash)
    {
        return password_get_info($hash);
    }

    /**
     * 创建密码的散列
     * @param string $password 密码
     * @param int    $algo     指示算法的密码算法常量
     * @param array  $options  选项
     * @return string 失败时返回 false
     */
    public static function hash($password, $algo, $options = null)
    {
        return password_hash($password, $algo, $options);
    }

    /**
     * 检测散列值是否匹配指定的选项
     * @param string $hash    散列值
     * @param int    $algo    指示算法的密码算法常量
     * @param array  $options 选项
     * @return bool
     */
    public static function needsRehash($hash, $algo, $options = null)
    {
        return password_needs_rehash($hash, $algo, $options);
    }

    /**
     * 验证密码是否和散列值匹配
     * @param string $password 密码
     * @param string $hash     散列值
     * @return bool
     */
    public static function verify($password, $hash)
    {
        return password_verify($password, $hash);
    }
}
