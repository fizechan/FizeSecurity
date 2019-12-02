<?php

namespace fize\security;

/**
 * 过滤器
 */
class Filter
{

    /**
     * 禁止实例化
     */
    private function __construct()
    {
    }

    /**
     * 判断是否有传递某参数
     *
     * 参数 `$type` :
     *   INPUT_GET, INPUT_POST, INPUT_COOKIE, INPUT_SERVER, or INPUT_ENV 值其中一个
     * @param int $type 类型
     * @param string $variable_name 参数名
     * @return bool
     */
    public static function hasVar($type, $variable_name)
    {
        return filter_has_var($type, $variable_name);
    }

    /**
     * 返回与某个特定名称的过滤器相关联的 id
     * @param string $filtername 过滤器名称
     * @return int
     */
    public static function id($filtername)
    {
        return filter_id($filtername);
    }

    /**
     * 获取一系列外部变量，并且可以通过过滤器处理它们
     *
     * 参数 `$type` :
     *   INPUT_GET, INPUT_POST, INPUT_COOKIE, INPUT_SERVER, or INPUT_ENV 值其中一个
     * @param int $type 类型
     * @param mixed $definition 定义过滤器参数
     * @param bool $add_empty 在返回值中添加 NULL 作为不存在的键。
     * @return mixed
     */
    public static function inputArray($type, $definition, $add_empty = true)
    {
        return filter_input_array($type, $definition, $add_empty);
    }

    /**
     * 通过名称获取特定的外部变量，并且可以通过过滤器处理它
     *
     * 参数 `$type` :
     *   INPUT_GET, INPUT_POST, INPUT_COOKIE, INPUT_SERVER, or INPUT_ENV 值其中一个
     * @param int $type 类型
     * @param string $variable_name 待获取的变量名
     * @param int $filter 指定过滤器
     * @param mixed $options 指定过滤器参数
     * @return mixed
     */
    public static function input($type, $variable_name, $filter = 516, $options = null)
    {
        return filter_input($type, $variable_name, $filter, $options);
    }

    /**
     * 返回所支持的过滤器列表
     * @return array
     */
    public static function list()
    {
        return filter_list();
    }

    /**
     * 获取多个变量并且过滤它们
     * @param array $data 一个键为字符串，值为待过滤的数据的数组
     * @param mixed $definition 一个定义参数的数组
     * @param bool $add_empty 在返回值中添加 NULL 作为不存在的键
     * @return mixed
     */
    public static function varArray($data, $definition, $add_empty = true)
    {
        return filter_var_array($data, $definition, $add_empty);
    }

    /**
     * 使用特定的过滤器过滤一个变量
     * @param mixed $variable 待过滤的变量
     * @param int $filter 指定过滤器 ID
     * @param mixed $options 指定过滤器参数
     * @return mixed
     */
    public static function var($variable, $filter = 516, $options = null)
    {
        return filter_var($variable, $filter, $options);
    }
}
