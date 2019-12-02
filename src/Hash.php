<?php

namespace fize\security;

/**
 * 哈希信息摘要
 */
class Hash
{

    /**
     * @var resource 当前哈希运算上下文资源
     */
    private $_resource;

    /**
     * 构造
     *
     * 参数 `$algo` :
     *   例如："md5"，"sha256"，"haval160,4" 等
     * 参数 `$options` :
     *   目前仅支持一个选项：HASH_HMAC
     * 参数 `$key` :
     *   使用此参数传入进行 HMAC 哈希运算时的共享密钥。
     * @param string $algo 要使用的哈希算法名称
     * @param int $options 进行哈希运算的可选设置
     * @param string $key 当 options 参数为 HASH_HMAC 时
     */
    public function __construct($algo, $options = 0, $key = null)
    {
        $this->_resource = self::init($algo, $options, $key);
    }

    /**
     * 返回已注册的哈希算法列表
     * @return array
     */
    public static function algos()
    {
        return hash_algos();
    }

    /**
     * 拷贝当前哈希运算上下文
     *
     * 参数 `$clone` :
     *   如果 $clone 为 true 则返回的是克隆的 Hash 类而非哈希运算上下文
     * @param bool $clone 是否克隆
     * @return mixed
     */
    public function copy($clone = true)
    {
        if ($clone) {
            return clone $this;
        } else {
            return hash_copy($this->_resource);
        }
    }

    /**
     * 可防止时序攻击的字符串比较
     *
     * 非常重要的一点是，用户提供的字符串必须是第二个参数。
     * @param string $known_string 已知长度的、要参与比较的字符串
     * @param string $user_string 用户提供的字符串
     * @return bool
     */
    public static function equals($known_string, $user_string)
    {
        return hash_equals($known_string, $user_string);
    }

    /**
     * 使用给定文件的内容生成哈希值
     *
     * 参数 `$algo` :
     *   例如："md5"，"sha256"，"haval160,4" 等。
     * 参数 `$filename` :
     *   支持 fopen 封装器。
     * 参数 `$raw_output` :
     *   设置为 TRUE，输出格式为原始的二进制数据。 设置为 FALSE，输出小写的 16 进制字符串。
     * @param string $algo 要使用的哈希算法的名称
     * @param string $filename 要进行哈希运算的文件路径
     * @param bool $raw_output 是否输出格式为原始的二进制数据
     * @return string
     */
    public static function file($algo, $filename, $raw_output = false)
    {
        return hash_file($algo, $filename, $raw_output);
    }

    /**
     * 结束增量哈希，并且返回摘要结果
     *
     * 参数 `$raw_output` :
     *   设置为 TRUE，输出格式为原始的二进制数据。 设置为 FALSE，输出小写的 16 进制字符串。
     * @param bool $raw_output 是否输出格式为原始的二进制数据
     * @return string
     */
    public function final($raw_output = false)
    {
        return hash_final($this->_resource, $raw_output);
    }

    /**
     * 使用 HMAC 方法和给定文件的内容生成带密钥的哈希值
     *
     * 参数 `$algo` :
     *   例如："md5"，"sha256"，"haval160,4" 等.
     * 参数 `$filename` :
     *   支持 fopen 封装器。
     * 参数 `$raw_output` :
     *   设置为 TRUE，输出格式为原始的二进制数据。 设置为 FALSE，输出小写的 16 进制字符串。
     * @param string $algo 要使用的哈希算法的名称
     * @param string $filename 要进行哈希运算的文件路径
     * @param string $key 使用 HMAC 生成信息摘要时所使用的密钥。
     * @param bool $raw_output 是否输出格式为原始的二进制数据
     * @return string
     */
    public static function hmacFile($algo, $filename, $key, $raw_output = false)
    {
        return hash_hmac_file($algo, $filename, $key, $raw_output);
    }

    /**
     * 使用 HMAC 方法生成带有密钥的哈希值
     *
     * 参数 `$algo` :
     *   例如："md5"，"sha256"，"haval160,4" 等。
     * 参数 `$raw_output` :
     *   设置为 TRUE，输出格式为原始的二进制数据。 设置为 FALSE，输出小写的 16 进制字符串。
     * @param string $algo 要使用的哈希算法的名称
     * @param string $data 要进行哈希运算的消息。
     * @param string $key 使用 HMAC 生成信息摘要时所使用的密钥。
     * @param bool $raw_output 是否输出格式为原始的二进制数据
     * @return string
     */
    public static function hmac($algo, $data, $key, $raw_output = false)
    {
        return hash_hmac($algo, $data, $key, $raw_output);
    }

    /**
     * 初始化增量哈希运算上下文
     *
     * 参数 `$algo` :
     *   例如："md5"，"sha256"，"haval160,4" 等。
     * 参数 `$options` :
     *   目前仅支持一个选项：HASH_HMAC
     * 参数 `$key` :
     *   当 options 参数为 HASH_HMAC 时， 使用此参数传入进行 HMAC 哈希运算时的共享密钥。
     * @param string $algo 要使用的哈希算法名称
     * @param int $options 进行哈希运算的可选设置
     * @param string $key 进行 HMAC 哈希运算时的共享密钥。
     * @return resource 返回哈希运算上下文资源
     */
    public static function init($algo, $options = 0, $key = null)
    {
        return hash_init($algo, $options, $key);
    }

    /**
     * 生成所提供密码的 PBKDF2 密钥导出
     *
     * 参数 `$algo` :
     *   例如："md5"，"sha256"，"haval160,4" 等。
     * 参数 `$salt` :
     *   这个值应该是随机生成的。
     * 参数 `$length` :
     *   默认0，则使用所选算法的完整输出大小。
     * 参数 `$raw_output` :
     *   设置为 TRUE，输出格式为原始的二进制数据。 设置为 FALSE，输出小写的 16 进制字符串。
     * @param string $algo 哈希算法名称
     * @param string $password 要进行导出的密码
     * @param string $salt 进行导出时所使用的“盐”
     * @param int $iterations 进行导出时的迭代次数
     * @param int $length 密钥导出数据的长度
     * @param bool $raw_output 是否输出格式为原始的二进制数据
     * @return string
     */
    public static function pbkdf2($algo, $password, $salt, $iterations, $length = 0, $raw_output = false)
    {
        return hash_pbkdf2($algo, $password, $salt, $iterations, $length, $raw_output);
    }

    /**
     * 从文件向活跃的哈希运算上下文中填充数据
     *
     * 参数 `$filename` :
     *   支持 fopen 封装器。
     * 参数 `$scontext` :
     *   由 stream_context_create() 函数返回的流上下文。
     * @param string $filename 要进行哈希运算的文件路径
     * @param resource $scontext 流上下文
     * @return bool
     */
    public function updateFile($filename, $scontext = null)
    {
        return hash_update_file($this->_resource, $filename, $scontext);
    }

    /**
     * 从打开的流向活跃的哈希运算上下文中填充数据
     *
     * 参数 `$length` :
     *   -1 表示全部返回。
     * @param resource $handle 创建流的函数返回的打开的文件句柄
     * @param int $length 要从 handle 向活跃的哈希运算上下文中拷贝的最大字符数
     * @return int 从 handle 向哈希运算上下文中实际填充的字节数量
     */
    public function updateStream($handle, $length = -1)
    {
        return hash_update_stream($this->_resource, $handle, $length);
    }

    /**
     * 向活跃的哈希运算上下文中填充数据
     * @param string $data 要向哈希摘要中追加的数据
     * @return bool
     */
    public function update($data)
    {
        return hash_update($this->_resource, $data);
    }
}
