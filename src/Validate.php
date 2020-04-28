<?php

namespace fize\security;

use Exception;
use SplFileObject;

/**
 * 验证
 */
class Validate
{

    /**
     * @var array 内置正则验证规则
     */
    protected static $regex = [
        'alphaDash'   => '/^[A-Za-z0-9\-\_]+$/',
        'chs'         => '/^[\x{4e00}-\x{9fa5}]+$/u',
        'chsAlpha'    => '/^[\x{4e00}-\x{9fa5}a-zA-Z]+$/u',
        'chsAlphaNum' => '/^[\x{4e00}-\x{9fa5}a-zA-Z0-9]+$/u',
        'chsDash'     => '/^[\x{4e00}-\x{9fa5}a-zA-Z0-9\_\-]+$/u',
        'mobile'      => '/^1[3-9][0-9]\d{8}$/',
        'idCard'      => '/(^[1-9]\d{5}(18|19|([23]\d))\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\d{3}[0-9Xx]$)|(^[1-9]\d{5}\d{2}((0[1-9])|(10|11|12))(([0-2][1-9])|10|20|30|31)\d{2}$)/',
        'zip'         => '/\d{6}/',
    ];

    /**
     * 正则验证
     * @param mixed  $value 字段值
     * @param string $rule  正则规则
     * @return bool
     */
    public static function regex($value, $rule)
    {
        if (0 !== strpos($rule, '/') && !preg_match('/\/[imsU]{0,4}$/', $rule)) {
            $rule = '/^' . $rule . '$/';
        }
        return is_scalar($value) && 1 === preg_match($rule, (string)$value);
    }

    /**
     * filter 验证
     * @param mixed $value   值
     * @param int   $filter  验证器 ID
     * @param mixed $options 其他参数
     * @return bool
     */
    public static function filter($value, $filter, $options = null)
    {
        return Filter::var($value, $filter, $options) !== false;
    }

    /**
     * 某个字段必须存在
     * @param string $name 键名
     * @param array  $sets 数组
     * @return bool
     */
    public static function isset($name, array $sets)
    {
        if (isset($sets[$name])) {
            return true;
        }
        return false;
    }

    /**
     * 是否为空
     * @param mixed $value 值
     * @return bool
     */
    public static function empty($value)
    {
        return empty($value);
    }

    /**
     * 是否不为空
     * @param mixed $value 值
     * @return bool
     */
    public static function notEmpty($value)
    {
        return !self::empty($value);
    }

    /**
     * 是否为 null
     * @param mixed $value 值
     * @return bool
     */
    public static function null($value)
    {
        return is_null($value);
    }

    /**
     * 是否不为 null
     * @param mixed $value 值
     * @return bool
     */
    public static function notNull($value)
    {
        return !self::null($value);
    }

    /**
     * 是否为纯数字，不包含负数和小数点
     * @param mixed $value 值
     * @return bool
     */
    public static function number($value)
    {
        return Ctype::digit((string)$value);
    }

    /**
     * 是否为整数
     * @param mixed $value 值
     * @return bool
     */
    public static function int($value)
    {
        return Filter::var($value, FILTER_VALIDATE_INT) !== false;
    }

    /**
     * 是否为浮点数字
     * @param mixed $value 值
     * @return bool
     */
    public static function float($value)
    {
        return Filter::var($value, FILTER_VALIDATE_FLOAT) !== false;
    }

    /**
     * 是否为布尔值
     * @param mixed $value 值
     * @return bool
     */
    public static function bool($value)
    {
        return Filter::var($value, FILTER_VALIDATE_BOOLEAN) !== false;
    }

    /**
     * 是否为 email 地址
     * @param mixed $value 值
     * @return bool
     */
    public static function email($value)
    {
        return Filter::var($value, FILTER_VALIDATE_EMAIL) !== false;
    }

    /**
     * 是否为数组
     * @param mixed $value 值
     * @return bool
     */
    public static function array($value)
    {
        return is_array($value);
    }

    /**
     * 是否为有效的日期、时间
     * @param mixed  $value  值
     * @param string $format 指定格式化
     * @return bool
     */
    public static function date($value, $format = null)
    {
        $time = strtotime($value);
        if (!$time) {
            return false;
        }
        if ($format) {
            return date($format, $time) == $value;
        }
        return true;
    }

    /**
     * 是否为纯字母
     * @param $value
     * @return bool
     */
    public static function alpha($value)
    {
        return Ctype::alpha($value);
    }

    /**
     * 是否为字母和数字
     * @param mixed $value 值
     * @return bool
     */
    public static function alphaNum($value)
    {
        return Ctype::alnum($value);
    }

    /**
     * 是否为字母和数字，下划线_及破折号 -
     * @param mixed $value 值
     * @return bool
     */
    public static function alphaDash($value)
    {
        return self::regex($value, self::$regex['alphaDash']);
    }

    /**
     * 只能是汉字
     * @param mixed $value 值
     * @return bool
     */
    public static function chs($value)
    {
        return self::regex($value, self::$regex['chs']);
    }

    /**
     * 只能是汉字、字母
     * @param mixed $value 值
     * @return bool
     */
    public static function chsAlpha($value)
    {
        return self::regex($value, self::$regex['chsAlpha']);
    }

    /**
     * 只能是汉字、字母和数字
     * @param mixed $value 值
     * @return bool
     */
    public static function chsAlphaNum($value)
    {
        return self::regex($value, self::$regex['chsAlphaNum']);
    }

    /**
     * 只能是汉字、字母、数字和下划线 _ 及破折号 -
     * @param mixed $value 值
     * @return bool
     */
    public static function chsDash($value)
    {
        return self::regex($value, self::$regex['chsDash']);
    }

    /**
     * 只能是控制字符（换行、缩进、空格）
     * @param mixed $value 值
     * @return bool
     */
    public static function cntrl($value)
    {
        return Ctype::cntrl($value);
    }

    /**
     * 只能是可打印字符（空格除外）
     * @param mixed $value 值
     * @return bool
     */
    public static function graph($value)
    {
        return Ctype::graph($value);
    }

    /**
     * 只能是可打印字符（包括空格）
     * @param mixed $value 值
     * @return bool
     */
    public static function print($value)
    {
        return Ctype::print($value);
    }

    /**
     * 只能是小写字符
     * @param mixed $value 值
     * @return bool
     */
    public static function lower($value)
    {
        return Ctype::lower($value);
    }

    /**
     * 只能是大写字符
     * @param mixed $value 值
     * @return bool
     */
    public static function upper($value)
    {
        return Ctype::upper($value);
    }

    /**
     * 只能是空白字符（包括缩进，垂直制表符，换行符，回车和换页字符）
     * @param mixed $value 值
     * @return bool
     */
    public static function space($value)
    {
        return Ctype::space($value);
    }

    /**
     * 只能是十六进制字符串
     * @param mixed $value 值
     * @return bool
     */
    public static function xdigit($value)
    {
        return Ctype::xdigit($value);
    }

    /**
     * 是否为有效的域名或者 IP
     * @param mixed  $value 值
     * @param string $rule  解析记录类型
     * @return bool
     */
    public static function dnsrr($value, $rule = 'MX')
    {
        if (!in_array($rule, ['A', 'MX', 'NS', 'SOA', 'PTR', 'CNAME', 'AAAA', 'A6', 'SRV', 'NAPTR', 'TXT', 'ANY'])) {
            $rule = 'MX';
        }
        return checkdnsrr($value, $rule);
    }

    /**
     * 是否为有效的 URL 地址
     * @param mixed $value 值
     * @return bool
     */
    public static function url($value)
    {
        return Filter::var($value, FILTER_VALIDATE_URL) !== false;
    }

    /**
     * 是否为有效的 IP 地址，支持验证 ipv4 和 ipv6 格式的IP地址。
     * @param mixed $value 值
     * @return bool
     */
    public static function ip($value)
    {
        return Filter::var($value, FILTER_VALIDATE_IP) !== false;
    }

    /**
     * 是否为有效的手机号码
     * @param mixed $value 值
     * @return bool
     */
    public static function mobile($value)
    {
        return self::regex($value, self::$regex['mobile']);
    }

    /**
     * 是否为有效的身份证格式
     * @param mixed $value 值
     * @return bool
     */
    public static function idCard($value)
    {
        return self::regex($value, self::$regex['idCard']);
    }

    /**
     * 是否为有效的 MAC 地址
     * @param mixed $value 值
     * @return bool
     */
    public static function macAddr($value)
    {
        return Filter::var($value, FILTER_VALIDATE_MAC) !== false;
    }

    /**
     * 是否为有效的邮政编码
     * @param mixed $value 值
     * @return bool
     */
    public static function zip($value)
    {
        return self::regex($value, self::$regex['zip']);
    }

    /**
     * 是否在指定数组内
     * @param mixed $value 值
     * @param array $sets  数组
     * @return bool
     */
    public static function in($value, array $sets)
    {
        return in_array($value, $sets);
    }

    /**
     * 是否不在指定数组内
     * @param mixed $value 值
     * @param array $sets  数组
     * @return bool
     */
    public static function notIn($value, array $sets)
    {
        $result = self::in($value, $sets);
        return !$result;
    }

    /**
     * 是否在某个区间
     * @param mixed $value 值
     * @param mixed $min   最小值
     * @param mixed $max   最大值
     * @return bool
     */
    public static function between($value, $min, $max)
    {
        return $value >= $min && $value <= $max;
    }

    /**
     * 是否不在某个区间
     * @param mixed $value 值
     * @param mixed $min   最小值
     * @param mixed $max   最大值
     * @return bool
     */
    public static function notBetween($value, $min, $max)
    {
        $result = self::between($value, $min, $max);
        return !$result;
    }

    /**
     * 验证数据长度
     * @param mixed $value 值
     * @param int   $min   最小长度
     * @param int   $max   最大长度，如果未设定该参数，则表示长度 = $min
     * @return bool
     */
    public static function length($value, $min, $max = null)
    {
        if (is_array($value)) {
            $length = count($value);
        } elseif ($value instanceof SplFileObject) {
            $length = $value->getSize();
        } else {
            $length = mb_strlen((string)$value);
        }

        if ($max) {// 长度区间
            return $length >= $min && $length <= $max;
        }
        // 指定长度
        return $length == $min;
    }

    /**
     * 值的最大长度
     * @param mixed $value 值
     * @param int   $max   最大长度
     * @return bool
     */
    public static function maxLength($value, $max)
    {
        return self::length($value, 0, $max);
    }

    /**
     * 值的最小长度
     * @param mixed $value 值
     * @param int   $min   最小长度
     * @return bool
     */
    public static function minLength($value, $min)
    {
        if (is_array($value)) {
            $length = count($value);
        } elseif ($value instanceof SplFileObject) {
            $length = $value->getSize();
        } else {
            $length = mb_strlen((string)$value);
        }
        return $length >= $min;
    }

    /**
     * 是否在某个日期之后
     * @param mixed  $value 值
     * @param string $date  日期时间
     * @return bool
     */
    public static function after($value, $date)
    {
        return strtotime($value) >= strtotime($date);
    }

    /**
     * 是否在某个日期之前
     * @param mixed  $value 值
     * @param string $date  日期时间
     * @return bool
     */
    public static function before($value, $date)
    {
        return strtotime($value) <= strtotime($date);
    }

    /**
     * 是否在某个有效日期之内
     * @param mixed  $value      值
     * @param string $date_begin 开始时间
     * @param string $date_end   结束时间
     * @return bool
     */
    public static function expire($value, $date_begin, $date_end)
    {
        return strtotime($value) >= strtotime($date_begin) && strtotime($value) <= strtotime($date_end);
    }

    /**
     * IP 是否属于指定网段
     *
     * 网段参数支持如下格式：
     *   - 单个 IP : 192.168.5.1
     *   - 带 * 号通配符 IP 格式：192.*.*.1
     *   - IP 段组：192.168.5.1 - 192.168.10.101
     * @param string $ip
     * @param array  $networks 网段数组
     * @return bool
     * @todo 仅支持IPV4，IPV6暂未实现
     */
    public static function inIp($ip, array $networks)
    {
        $ip_now = ip2long($ip);
        foreach ($networks as $network) {
            // 1.判断单个IP
            if ($ip == $network) {
                return true;
            }
            // 2.判断带*号通配符IP格式
            if (strpos($network, '*') !== false) {
                $ip_pds = explode('.', $ip);
                $network_pds = explode('.', $network);
                $same = true;
                foreach ($network_pds as $index => $network_pd) {
                    if ($network_pd == '*') {
                        continue;
                    }
                    if ($network_pd != $ip_pds[$index]) {
                        $same = false;
                        break;
                    }
                }
                if ($same) {
                    return true;
                }
            }
            // 3.判断IP段组
            if (strpos($network, '-') !== false) {
                $tmp = explode('-', $network);
                $ip_begin = ip2long($tmp[0]);
                $ip_end = ip2long($tmp[1]);

                if ($ip_now >= $ip_begin && $ip_now <= $ip_end) {
                    return true;
                }
            }

        }

        return false;
    }

    /**
     * 判断值是否和指定数组指定键名的值相同
     * @param mixed  $value 值
     * @param string $name  指定键名
     * @param array  $array 指定数组
     * @return bool
     */
    public static function confirm($value, $name, array $array)
    {
        return $value == $array[$name];
    }

    /**
     * 判断值是否和指定数组指定键名的值不相同
     * @param mixed  $value 值
     * @param string $name  指定键名
     * @param array  $array 指定数组
     * @return bool
     */
    public static function different($value, $name, array $array)
    {
        return $value != $array[$name];
    }

    /**
     * 判断值是否大于等于指定数组指定键名的值
     * @param mixed  $value 值
     * @param array  $array 指定数组
     * @param string $name  指定键名
     * @return bool
     */
    public static function fieldEgt($value, array $array, $name)
    {
        return $value >= $array[$name];
    }

    /**
     * 判断值是否大于指定数组指定键名的值
     * @param mixed  $value 值
     * @param array  $array 指定数组
     * @param string $name  指定键名
     * @return bool
     */
    public static function fieldGt($value, array $array, $name)
    {
        return $value > $array[$name];
    }

    /**
     * 判断值是否小于等于指定数组指定键名的值
     * @param mixed  $value 值
     * @param array  $array 指定数组
     * @param string $name  指定键名
     * @return bool
     */
    public static function fieldElt($value, array $array, $name)
    {
        return $value <= $array[$name];
    }

    /**
     * 判断值是否小于指定数组指定键名的值
     * @param mixed  $value 值
     * @param array  $array 指定数组
     * @param string $name  指定键名
     * @return bool
     */
    public static function fieldLt($value, array $array, $name)
    {
        return $value < $array[$name];
    }

    /**
     * 判断值是否等于预期值
     * @param mixed $value  值
     * @param mixed $expect 预期值
     * @return bool
     */
    public static function eq($value, $expect)
    {
        return $value == $expect;
    }

    /**
     * 判断值是否不等于预期值
     * @param mixed $value  值
     * @param mixed $expect 预期值
     * @return bool
     */
    public static function neq($value, $expect)
    {
        return $value != $expect;
    }

    /**
     * 判断值是否大于等于预期值
     * @param mixed $value  值
     * @param mixed $expect 预期值
     * @return bool
     */
    public static function egt($value, $expect)
    {
        return $value >= $expect;
    }

    /**
     * 判断值是否大于预期值
     * @param mixed $value  值
     * @param mixed $expect 预期值
     * @return bool
     */
    public static function gt($value, $expect)
    {
        return $value > $expect;
    }

    /**
     * 判断值是否小于等于预期值
     * @param mixed $value  值
     * @param mixed $expect 预期值
     * @return bool
     */
    public static function elt($value, $expect)
    {
        return $value <= $expect;
    }

    /**
     * 判断值是否小于预期值
     * @param mixed $value  值
     * @param mixed $expect 预期值
     * @return bool
     */
    public static function lt($value, $expect)
    {
        return $value < $expect;
    }

    /**
     * 判断值是否是文件对象
     * @param mixed $value 值
     * @return bool
     */
    public static function file($value)
    {
        return $value instanceof SplFileObject;
    }

    /**
     * 判断图像类型
     * @param string $image 图片文件路径
     * @return int 失败时返回 false
     */
    protected static function getImageType($image)
    {
        if (function_exists('exif_imagetype')) {
            return exif_imagetype($image);
        }

        try {
            $info = getimagesize($image);
            return $info ? $info[2] : false;
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * 判断是否为图片文件对象
     * @param mixed $value 值
     * @return bool
     */
    public static function image($value)
    {
        return $value instanceof SplFileObject && in_array(self::getImageType($value->getRealPath()), [1, 2, 3, 6]);
    }
}
