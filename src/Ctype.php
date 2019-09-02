<?php

namespace fize\security;

/**
 * 字符类型检测
 * @package fize\security
 */
class Ctype
{

    /**
     * 禁止实例化
     */
    private function __construct()
    {
    }

    /**
     * 做字母和数字字符检测，判断是否全部为字母和(或)数字字符。
     * @param string $text 待判断字符串
     * @return bool
     */
    public static function alnum($text)
    {
        return ctype_alnum($text);
    }

    /**
     * 判断字符串是否为全字母
     * @param string $text 待判断字符串
     * @return bool
     */
    public static function alpha($text)
    {
        return ctype_alpha($text);
    }

    /**
     * 检查提供的 string 和 text 里面的字符是不是都是控制字符。 控制字符就是例如：换行、缩进、空格。
     * @param string $text 待判断字符串
     * @return bool
     */
    public static function cntrl($text)
    {
        return ctype_cntrl($text);
    }

    /**
     * 判断提供的字符串是不是纯数字，注意传入的必须是string类型，传入int会导致判断错误
     * @param string $text 待判断字符串
     * @return bool
     */
    public static function digit($text)
    {
        return ctype_digit($text);
    }

    /**
     * 做可打印字符串检测，空格除外
     * @param string $text 待判断字符串
     * @return bool
     */
    public static function graph($text)
    {
        return ctype_graph($text);
    }

    /**
     * 做小写字符检测
     * @param string $text 待判断字符串
     * @return bool
     */
    public static function lower($text)
    {
        return ctype_lower($text);
    }

    /**
     * 做可打印字符检测
     * @param string $text 待判断字符串
     * @return bool
     */
    public static function canPrint($text)
    {
        return ctype_print($text);
    }

    /**
     * 检测可打印的字符是不是不包含空白、数字和字母
     * @param string $text 待判断字符串
     * @return bool
     */
    public static function punct($text)
    {
        return ctype_punct($text);
    }

    /**
     * 做空白字符检测
     * @param string $text 待判断字符串
     * @return bool
     */
    public static function space($text)
    {
        return ctype_space($text);
    }

    /**
     * 做大写字母检测
     * @param string $text 待判断字符串
     * @return bool
     */
    public static function upper($text)
    {
        return ctype_upper($text);
    }

    /**
     * 检测字符串是否只包含十六进制字符
     * @param string $text 待判断字符串
     * @return bool
     */
    public static function xdigit($text)
    {
        return ctype_xdigit($text);
    }
}
