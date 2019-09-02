<?php

namespace fize\security;

use Exception;

/**
 *  OpenSSL扩展
 * 必须安装有效的 openssl.cnf 以保证此类正确运行
 * @todo pkcs7、pkey、spki、x509系列方法尚未测试
 * @package fize\security
 */
class OpenSSL
{

    /**
     * @var mixed CSR
     */
    private $csr = null;

    /**
     * @var string 密钥
     */
    private $key = null;

    /**
     * @var resource 私钥和公钥对
     */
    private $pkey = null;

    /**
     * @var resource 私钥
     */
    private $privateKey = null;

    /**
     * @todo 待优化
     * @var array 私钥信息，用于存储私钥密码及路径等
     */
    private $privateKeyInfo = [];

    /**
     * @var resource 公钥
     */
    private $publicKey = null;

    /**
     * @var mixed X.509证书
     */
    private $x509 = null;

    /**
     * @var array 接收方公钥
     */
    private $toPublicKeys = [];

    /**
     * 构造
     */
    public function __construct()
    {
    }

    /**
     * 析构
     */
    public function __destruct()
    {
        if (is_resource($this->publicKey)) {
            self::freeKey($this->publicKey);
        }
        if (is_resource($this->privateKey)) {
            self::freeKey($this->privateKey);
        }
        if ($this->toPublicKeys) {
            foreach ($this->toPublicKeys as $toPublicKey) {
                self::freeKey($toPublicKey);
            }
        }
        if (is_resource($this->pkey)) {
            $this->pkeyFree();
        }
    }

    /**
     * 设置CSR
     * @param mixed $csr CSR资源对象或者CSR字符串或则CSR文件的路径
     * @param bool $is_file 指明参数$csr是否为文件路径，默认true
     * @return bool
     */
    public function setCsr($csr, $is_file = true)
    {
        if (!is_resource($csr)) {
            if ($is_file) {
                $csr = file_get_contents($csr);
            }
            if ($csr === false) {
                return false;
            }
        }
        $this->csr = $csr;
        return true;
    }

    /**
     * 设置密钥
     * @param string $key 密钥
     */
    public function setKey($key)
    {
        $this->key = $key;
    }

    /**
     * 设置私钥公钥对
     * @param resource $pkey
     */
    public function setPkey($pkey)
    {
        $this->pkey = $pkey;
    }

    /**
     * 设置公钥
     * @param mixed $key 公钥字符串或则公钥文件的路径或者公钥资源对象
     * @param bool $is_file 指明参数$key是否为文件路径，默认true
     * @return bool
     */
    public function setPublicKey($key, $is_file = true)
    {
        if (is_resource($key)) {
            $res = $key;
        } else {
            if ($is_file) {
                $key = file_get_contents($key);
            }
            $res = self::pkeyGetPublic($key);
            if ($res === false) {
                return false;
            }
        }
        $this->publicKey = $res;
        return true;
    }

    /**
     * 设置私钥
     * @param mixed $key 私钥字符串或则私钥文件的路径或者密钥资源对象
     * @param bool $is_file 指明参数$key是否为文件路径，默认true
     * @param string $passphrase 如果指定的密钥已被加密了(受密码保护)，可选参数 passphrase 是必须要的
     * @return bool
     */
    public function setPrivateKey($key, $is_file = true, $passphrase = '')
    {
        if (is_resource($key)) {
            $res = $key;
        } else {
            if ($is_file) {
                $key = file_get_contents($key);
            }
            $res = self::pkeyGetPrivate($key, $passphrase);
            if ($res === false) {
                return false;
            }
            $this->privateKeyInfo = [$key, $passphrase];
        }
        $this->privateKey = $res;
        return true;
    }

    /**
     * 设置X509证书
     * @param mixed $x509 X509证书资源对象或者证书字符串或则证书文件的路径
     * @param bool $is_file 指明参数$x509是否为文件路径，默认true
     * @return bool
     */
    public function setX509($x509, $is_file = true)
    {
        if (!is_resource($x509)) {
            if ($is_file) {
                $x509 = file_get_contents($x509);
            }
            if ($x509 === false) {
                return false;
            }
        }
        $this->x509 = $x509;
        return true;
    }

    /**
     * 设置接收方公钥
     * @param array $keys 要接收的公钥
     * @return array
     */
    public function setToPublicKeys(array $keys)
    {
        $to_public_keys = [];
        foreach ($keys as $key) {
            if (is_array($key)) {
                $certificate = $key['certificate'];
                $from_private = isset($key['from_private']) ? $key['from_private'] : false;
                $passphrase = isset($key['passphrase']) ? $key['passphrase'] : '';
                $to_public_key = self::pkeyGetPublic($certificate, $from_private, $passphrase);
            } else {
                $certificate = $key;
                $to_public_key = self::pkeyGetPublic($certificate);
            }
            $to_public_keys[] = $to_public_key;
        }
        $this->toPublicKeys = $to_public_keys;
        return $to_public_keys;
    }

    /**
     * 获取密码初始化向量（IV）长度。
     * @param string $method 密码的方法，更多值查看 openssl_get_cipher_methods() 函数。
     * @return int 失败时返回false
     */
    public static function cipherIvLength($method)
    {
        return openssl_cipher_iv_length($method);
    }

    /**
     * 将CSR导出到文件
     * @param string $outfilename 输出文件的路径
     * @param bool $notext 如果设为 FALSE，输出内容将包含附加的人类可读信息。notext 的缺省值为 TRUE。
     * @return bool
     */
    public function csrExportToFile($outfilename, $notext = true)
    {
        return openssl_csr_export_to_file($this->csr, $outfilename, $notext);
    }

    /**
     * 将CSR作为字符串导出
     * @param string $out 在成功时，该字符串将包含PEM编码的CSR.
     * @param bool $notext 如果设为 FALSE，输出内容将包含附加的人类可读信息。notext 的缺省值为 TRUE。
     * @return bool
     */
    public function csrExport(&$out, $notext = true)
    {
        return openssl_csr_export($this->csr, $out, $notext);
    }

    /**
     * 返回CSR的公钥
     * @param bool $use_shortnames 是否使用短名称
     * @return resource
     */
    public function csrGetPublicKey($use_shortnames = true)
    {
        return openssl_csr_get_public_key($this->csr, $use_shortnames);
    }

    /**
     * 返回CSR的主题
     * @param bool $use_shortnames 是否使用短名称
     * @return array
     */
    public function csrGetSubject($use_shortnames = true)
    {
        return openssl_csr_get_subject($this->csr, $use_shortnames);
    }

    /**
     * 生成一个 CSR
     * @param array $dn 在证书中使用的专有名称或主题字段
     * @param array $configargs 配置项
     * @param array $extraattribs 额外配置选项
     * @return resource 失败返回false
     */
    public function csrNew(array $dn, array $configargs = null, array $extraattribs = null)
    {
        return openssl_csr_new($dn, $this->privateKey, $configargs, $extraattribs);
    }

    /**
     * 用另一个证书签署 CSR (或者本身) 并且生成一个证书
     * @param int $days 指定生成的证书在几天内有效的时间长度
     * @param array $configargs 你可以通过configargs确定CSR签名
     * @param int $serial 可选的发行证书编号。如果没有指定默认值为0
     * @return resource
     */
    public function csrSign($days, array $configargs = null, $serial = 0)
    {
        return openssl_csr_sign($this->csr, $this->x509, $this->privateKeyInfo, $days, $configargs, $serial);
    }

    /**
     * 解密数据
     * @param string $data 将被解密的密文
     * @param string $method 加密算法
     * @param int $options 常量OPENSSL_RAW_DATA, OPENSSL_ZERO_PADDING中的一个
     * @param string $iv 非空的初始化向量
     * @param string $tag AEAD密码模式中的身份验证标签。 如果是错误的，验证失败，函数返回FALSE
     * @param string $aad 额外的认证数据
     * @return string 失败时返回false
     */
    public function decrypt($data, $method, $options = 0, $iv = "", $tag = "", $aad = "")
    {
        if (empty($iv)) {
            $ivlen = self::cipherIvLength($method);
            $iv = self::randomPseudoBytes($ivlen);
        }
        return openssl_decrypt($data, $method, $this->key, $options, $iv, $tag, $aad);
    }

    /**
     * 计算远程DH密钥(公钥)和本地DH密钥的共享密钥
     * @param resource $dh_key DH密钥
     * @return string
     * @todo 待验证
     */
    public function dhComputeKey($dh_key)
    {
        return openssl_dh_compute_key($this->publicKey, $dh_key);
    }

    /**
     * 计算摘要
     * @param string $data 给定的数据
     * @param string $method 要使用的摘要方法
     * @param bool $raw_output 为 TRUE 时将会返回原始输出数据，否则返回值将会是16进制
     * @return string
     */
    public static function digest($data, $method, $raw_output = false)
    {
        return openssl_digest($data, $method, $raw_output);
    }

    /**
     * 加密数据
     * @param string $data 待加密的明文信息数据
     * @param string $method 密码学方式
     * @param int $options 常量OPENSSL_RAW_DATA, OPENSSL_ZERO_PADDING中的一个
     * @param string $iv 非NULL的初始化向量
     * @param bool $is_aead 是否使用使用AEAD密码模式
     * @param string $tag 使用AEAD密码模式（GCM 或 CCM）时传引用的验证标签
     * @param string $aad 附加的验证数据
     * @param int $tag_length 验证 tag 的长度。GCM 模式时，它的范围是 4 到 16
     * @return string
     */
    public function encrypt($data, $method, $options = 0, $iv = "", $is_aead = false, &$tag = null, $aad = "", $tag_length = 16)
    {
        if (empty($iv)) {
            $ivlen = self::cipherIvLength($method);
            $iv = self::randomPseudoBytes($ivlen);
        }
        if ($is_aead) {
            return openssl_encrypt($data, $method, $this->key, $options, $iv, $tag, $aad, $tag_length);
        }
        return openssl_encrypt($data, $method, $this->key, $options, $iv);
    }

    /**
     * 返回openSSL错误消息
     * @return string
     */
    public static function errorString()
    {
        return openssl_error_string();
    }

    /**
     * 释放密钥资源
     * @param resource $key_identifier 标识
     */
    public static function freeKey($key_identifier)
    {
        return openssl_free_key($key_identifier);
    }

    /**
     * 检索可用的证书位置
     * @return array
     */
    public static function getCertLocations()
    {
        return openssl_get_cert_locations();
    }

    /**
     * 获取可用的加密算法
     * @param bool $aliases 如果密码别名应该包含在返回的array中，则设置为 TRUE
     * @return array
     */
    public static function getCipherMethods($aliases = false)
    {
        return openssl_get_cipher_methods($aliases);
    }

    /**
     * 获得ECC的可用曲线名称列表
     */
    public static function getCurveNames()
    {
        return openssl_get_curve_names();
    }

    /**
     * 获取可用的摘要算法
     * @param bool $aliases 设置为 TRUE 时，返回的array中将会包含摘要的别名.
     * @return array
     */
    public static function getMdMethods($aliases = false)
    {
        return openssl_get_md_methods($aliases);
    }

    /**
     * 获取私钥
     * @param mixed $key 格式字符串“file://path/to/file.pem”或者PEM格式的私钥
     * @param string $passphrase 如果指定的密钥已被加密了(受密码保护)，可选参数 passphrase 是必须要的
     * @return resource 失败返回false
     * @deprecated openssl_pkey_get_private()的别名，不建议使用
     */
    public static function getPrivatekey($key, $passphrase = "")
    {
        return self::pkeyGetPrivate($key, $passphrase);
    }

    /**
     * 从证书中解析公钥，以供使用
     * @param mixed $certificate X.509证书资源或者格式字符串“file://path/to/file.pem”或者PEM格式的公钥
     * @return resource
     * @deprecated openssl_pkey_get_public()的别名，不建议使用
     */
    public static function getPublickey($certificate)
    {
        return self::pkeyGetPublic($certificate);
    }

    /**
     * 打开密封的数据
     * @param string $sealed_data 待解密数据
     * @param string $open_data 如果调用成功，则在这个参数中返回打开的数据
     * @param string $env_key 信封密钥
     * @param string $method 加解密算法
     * @param string $iv 初始化向量
     * @return bool
     */
    public function open($sealed_data, &$open_data, $env_key, $method = "RC4", &$iv = null)
    {
        return openssl_open($sealed_data, $open_data, $env_key, $this->privateKey, $method, $iv);
    }

    /**
     * 生成一个 PKCS5 v2 PBKDF2 字符串
     * @param string $password 派生密钥所生成的密码
     * @param string $salt PBKDF2推荐一个不少于64位(8字节)的密码盐值
     * @param int $key_length 希望输出密钥的长度
     * @param int $iterations 需要的迭代次数 » NIST 建议至少10,000次.
     * @param string $digest_algorithm 可选的散列或摘要算法.默认是 SHA-1.
     * @return string 失败时返回false
     */
    public static function pbkdf2($password, $salt, $key_length, $iterations, $digest_algorithm = 'sha1')
    {
        return openssl_pbkdf2($password, $salt, $key_length, $iterations, $digest_algorithm);
    }

    /**
     * 输出一个 PKCS#12 兼容的证书存储文件
     * @param string $filename 输出文件的路径
     * @param string $pass 用于解锁 PKCS#12 文件的加密密码
     * @param array $args 可选数组
     * @return bool
     */
    public function pkcs12ExportToFile($filename, $pass, array $args = null)
    {
        if ($args) {
            return openssl_pkcs12_export_to_file($this->x509, $filename, $this->privateKey, $pass, $args);
        } else {
            return openssl_pkcs12_export_to_file($this->x509, $filename, $this->privateKey, $pass);
        }
    }

    /**
     * 将 PKCS#12 兼容证书存储文件导出到变量
     * @param string $out 成功，该字符串将为 PKCS#12 格式
     * @param string $pass 用于解锁 PKCS#12 文件的加密密码
     * @param array $args 可选数组
     * @return bool
     */
    public function pkcs12Export(&$out, $pass, array $args = null)
    {
        if ($args) {
            return openssl_pkcs12_export($this->x509, $out, $this->privateKey, $pass, $args);
        } else {
            return openssl_pkcs12_export($this->x509, $out, $this->privateKey, $pass);
        }
    }

    /**
     * 将 PKCS#12 证书存储区解析到数组中
     * @param string $pkcs12 证书存储内容
     * @param array $certs 成功，将保存证书存储数据
     * @param string $pass 用来解锁PKCS#12文件的解密密码
     * @return bool
     */
    public static function pkcs12Read($pkcs12, &$certs, $pass)
    {
        return openssl_pkcs12_read($pkcs12, $certs, $pass);
    }

    /**
     * 解密一个S/MIME加密的消息
     * @param string $infilename 加密信息文件路径
     * @param string $outfilename 解密的消息将被存入的文件中，以outfilename命名
     * @return bool
     */
    public function pkcs7Decrypt($infilename, $outfilename)
    {
        return openssl_pkcs7_decrypt($infilename, $outfilename, $this->x509, $this->privateKey);
    }

    /**
     * 加密一个S/MIME消息
     * @param string $infile 加密信息文件路径
     * @param string $outfile 加密的消息将被存入的文件中，以outfilename命名
     * @param array $headers 包含头信息的数组，在被加密后将对数据进行预处理
     * @param mixed $recipcerts 一个X.509证书[或数组]，不指定则为当前证书
     * @param int $flags 指定影响编码过程的选项
     * @param int $cipherid 密码常量之一
     * @return bool
     */
    public function pkcs7Encrypt($infile, $outfile, array $headers, $recipcerts = null, $flags = 0, $cipherid = 0)
    {
        if (is_null($recipcerts)) {
            $recipcerts = $this->x509;
        }
        return openssl_pkcs7_encrypt($infile, $outfile, $recipcerts, $headers, $flags, $cipherid);
    }

    /**
     * 将PKCS7文件导出为PEM格式证书的数组
     * @param string $infilename PKCS7文件路径
     * @param array $certs 成功后PEM格式证书的数组
     * @return bool
     */
    public static function pkcs7Read($infilename, array &$certs)
    {
        return openssl_pkcs7_read($infilename, $certs);
    }

    /**
     * 对一个S/MIME消息进行签名
     * @param string $infilename 你打算用来进行数字签名的输入文件
     * @param string $outfilename 将写入数字签名的文件
     * @param array $headers 个包含头信息的数组
     * @param int $flags 可以用来改变输出
     * @param string $extracerts 指定一个文件的名称，其中包含一组含有签名的额外的证书
     * @return bool
     */
    public function pkcs7Sign($infilename, $outfilename, array $headers, $flags = 64, $extracerts = null)
    {
        return openssl_pkcs7_sign($infilename, $outfilename, $this->x509, $this->privateKey, $headers, $flags, $extracerts);
    }

    /**
     * 校验一个已签名的S/MIME消息的签名
     * @param string $filename 消息文件的路径
     * @param int $flags 可以用来影响如何校验签名
     * @param string $outfilename 如果已指定 outfilename 输出文件，它应该是一个用以保存文件的字符串名称，签名消息的个人证书将以PEM的格式保存起来
     * @param array $cainfo 保存关于受信任的CA证书的信息供在验证过程中使用
     * @param string $extracerts 如果 extracerts 被指定了，该文件包含了一堆会被作为不受信任的ca使用的证书
     * @param string $content 你可以使用 content 来指定带有已被验证数据的文件名，该文件内容已去掉了签名信息
     * @return bool 错误时返回1
     */
    public function pkcs7Verify($filename, $flags, $outfilename = null, array $cainfo = null, $extracerts = null, $content = null)
    {
        if (is_null($cainfo)) {
            $cainfo = $this->x509;
        }
        return openssl_pkcs7_verify($filename, $flags, $outfilename, $cainfo, $extracerts, $content);
    }

    /**
     * 将密钥导出到文件中
     * @param string $outfilename 输出文件的路径
     * @param string $passphrase 密钥可以通过值为passphrase的密码来保护
     * @param array $configargs 用来调整导出流程，通过指定或者覆盖openssl配置文件选项
     * @return bool
     */
    public function pkeyExportToFile($outfilename, $passphrase = null, array $configargs = null)
    {
        return openssl_pkey_export_to_file($this->pkey, $outfilename, $passphrase, $configargs);
    }

    /**
     * 将一个密钥的可输出表示转换为字符串
     * @param string $out 成功时该变量取得字符串内容
     * @param string $passphrase 密钥可以通过 passphrase 来保护
     * @param array $configargs 用来调整导出流程，通过指定或者覆盖openssl配置文件选项
     * @return bool
     */
    public function pkeyExport(&$out, $passphrase = null, array $configargs = null)
    {
        return openssl_pkey_export($this->pkey, $out, $passphrase, $configargs);
    }

    /**
     * 释放私钥
     */
    public function pkeyFree()
    {
        return openssl_pkey_free($this->pkey);
    }

    /**
     * 返回包含密钥详情的数组
     * @return array
     */
    public function pkeyGetDetails()
    {
        return openssl_pkey_get_details($this->pkey);
    }

    /**
     * 获取私钥
     * @param mixed $key 格式字符串“file://path/to/file.pem”或者PEM格式的私钥
     * @param string $passphrase 如果指定的密钥已被加密了(受密码保护)，可选参数 passphrase 是必须要的
     * @return resource 失败返回false
     */
    public static function pkeyGetPrivate($key, $passphrase = "")
    {
        return openssl_pkey_get_private($key, $passphrase);
    }

    /**
     * 从证书中解析公钥，以供使用
     * @param mixed $certificate X.509证书资源或者格式字符串“file://path/to/file.pem”或者PEM格式的公钥
     * @param bool $from_private 指明$certificate是否为私钥
     * @param string $passphrase 如果指定的密钥已被加密了(受密码保护)，可选参数 passphrase 是必须要的
     * @return resource 失败返回false
     */
    public static function pkeyGetPublic($certificate, $from_private = false, $passphrase = "")
    {
        if ($from_private) {
            $pkey = openssl_pkey_get_private($certificate, $passphrase);
            $details = openssl_pkey_get_details($pkey);
            return openssl_get_publickey($details['key']);
        }
        return openssl_get_publickey($certificate);
    }

    /**
     * 生成一个新的私钥
     * @param array $configargs 使用configargs参数微调密钥的生成
     * @return resource 错误时返回false
     */
    public static function pkeyNew(array $configargs = null)
    {
        return openssl_pkey_new($configargs);
    }

    /**
     * 使用私钥解密数据
     * @param string $data 待解密数据
     * @param int $padding 常量之一
     * @return string 返回解密结果
     */
    public function privateDecrypt($data, $padding = 1)
    {
        $result = openssl_private_decrypt($data, $decrypted, $this->privateKey, $padding);
        if (!$result) {
            throw new Exception(self::errorString());
        }
        return $decrypted;
    }

    /**
     * 使用私钥加密数据
     * @notice 只能加密短字符串，长字符串请使用AES加密
     * @param string $data 待加密数据
     * @param int $padding 常量之一
     * @return string 返回加密结果
     */
    public function privateEncrypt($data, $padding = 1)
    {
        $result = openssl_private_encrypt($data, $crypted, $this->privateKey, $padding);
        if (!$result) {
            throw new Exception(self::errorString());
        }
        return $crypted;
    }

    /**
     * 使用公钥解密数据
     * @param string $data 待解密数据
     * @param int $padding 常量之一
     * @return string 返回解密结果
     */
    public function publicDecrypt($data, $padding = 1)
    {
        $result = openssl_public_decrypt($data, $decrypted, $this->publicKey, $padding);
        if (!$result) {
            throw new Exception(self::errorString());
        }
        return $decrypted;
    }

    /**
     * 使用公钥加密数据
     * @notice 只能加密短字符串，长字符串请使用AES加密
     * @param string $data 待加密数据
     * @param int $padding 常量之一
     * @return string 返回加密结果
     */
    public function publicEncrypt($data, $padding = 1)
    {
        $result = openssl_public_encrypt($data, $crypted, $this->publicKey, $padding);
        if (!$result) {
            throw new Exception(self::errorString());
        }
        return $crypted;
    }

    /**
     * 生成一个伪随机字节串
     * @param int $length 所需字节串的长度
     * @param bool $crypto_strong 如果传递到该函数中，将会保存为一个 boolean 值来表明是否使用了"强加密"
     * @return string
     */
    public static function randomPseudoBytes($length, &$crypto_strong = null)
    {
        return openssl_random_pseudo_bytes($length, $crypto_strong);
    }

    /**
     * 密封 (加密) 数据
     * @param string $data 要密封的数据
     * @param string $sealed_data 保存被密封后的数据
     * @param array $env_keys 保存已被加密的密钥数组
     * @param string $method 加密算法
     * @param string $iv 初始化向量
     * @return int
     */
    public function seal($data, &$sealed_data, array &$env_keys, $method = 'RC4', $iv = '')
    {
        return openssl_seal($data, $sealed_data, $env_keys, $this->toPublicKeys, $method, $iv);
    }

    /**
     * 对数据签名
     * @param string $data 待签名数据
     * @param int $signature_alg 签名参数
     * @return string 返回签名字符串
     */
    public function sign($data, $signature_alg = 1)
    {
        $result = openssl_sign($data, $signature, $this->privateKey, $signature_alg);
        if ($result === false) {
            throw new Exception(self::errorString());
        }
        return $signature;
    }

    /**
     * 导出与签名公钥和挑战相关的挑战字符串
     * @param string $spkac 包含一个可用的签名公钥和挑战
     * @return string 失败返回null
     */
    public static function spkiExportChallenge(&$spkac)
    {
        return openssl_spki_export_challenge($spkac);
    }

    /**
     * 通过签名公钥和挑战导出一个可用的PEM格式的公钥
     * @param string $spkac 期望一个有效的签名公钥和挑战字符串
     * @return string 失败返回null
     */
    public static function spkiExport(&$spkac)
    {
        return openssl_spki_export($spkac);
    }

    /**
     * 生成一个新的签名公钥和挑战
     * @param string $challenge 与SPKAC有关的挑战
     * @param int $algorithm 摘要算法
     * @return string
     */
    public function spki_new(&$challenge, $algorithm = 0)
    {
        return openssl_spki_new($this->privateKey, $challenge, $algorithm);
    }

    /**
     * 验证签名公钥和挑战
     * @param string $spkac 期望一个有效的签名公钥和挑战
     * @return bool
     */
    public static function spki_verify(&$spkac)
    {
        return openssl_spki_verify($spkac);
    }

    /**
     * 验证签名
     * @param string $data 用来生成签名的数据字符串
     * @param string $signature 签名
     * @param int $signature_alg 签名算法
     * @return bool 如果签名正确返回 true, 签名错误返回 false
     */
    public function verify($data, $signature, $signature_alg = 1)
    {
        $result = openssl_verify($data, $signature, $this->publicKey, $signature_alg);
        if ($result === -1) {
            throw new Exception(self::errorString());
        }
        return $result ? true : false;
    }

    /**
     * 检查私钥是否对应于证书
     * @return bool
     */
    public function x509CheckPrivateKey()
    {
        return openssl_x509_check_private_key($this->csr, $this->privateKey);
    }

    /**
     * 验证是否可以为特定目的使用证书
     * @param int $purpose 常量X509_PURPOSE_*
     * @param array $cainfo 一个受信任的CA文件/文件夹组成的数组
     * @param string $untrustedfile 如果指定，这应该是PEM编码文件的名称
     * @return int
     */
    public function x509Checkpurpose($purpose, array $cainfo = null, $untrustedfile = null)
    {
        return openssl_x509_checkpurpose($this->csr, $purpose, $cainfo, $untrustedfile);
    }

    /**
     * 导出证书至文件
     * @param string $outfilename 输出文件的路径
     * @param bool $notext 影响输出的冗余度
     * @return bool
     */
    public function x509ExportToFile($outfilename, $notext = true)
    {
        return openssl_x509_export_to_file($this->x509, $outfilename, $notext);
    }

    /**
     * 以字符串格式导出证书
     * @param string $output 成功，将会存储PEM
     * @param bool $notext 影响输出的冗余度
     * @return bool
     */
    public function x509Export(&$output, $notext = true)
    {
        return openssl_x509_export($this->x509, $output, $notext);
    }

    /**
     * 计算一个给定的x.509证书的指纹或摘要
     * @param string $hash_algorithm 使用的摘要方法或散列算法
     * @param bool $raw_output 设置为 TRUE时，输出原始二进制数据
     * @return string 失败返回false
     */
    public function x509Fingerprint($hash_algorithm = 'sha1', $raw_output = false)
    {
        return openssl_x509_fingerprint($this->x509, $hash_algorithm, $raw_output);
    }

    /**
     * 释放证书资源
     */
    public function x509Free()
    {
        return openssl_x509_free($this->x509);
    }

    /**
     * 解析一个X509证书并作为一个数组返回信息
     * @param bool $shortnames 控制数据在数组中的索引
     * @return array
     */
    public function x509Parse($shortnames = true)
    {
        return openssl_x509_parse($this->x509, $shortnames);
    }

    /**
     * 解析一个x.509证书并返回一个资源标识符
     * @param mixed $x509certdata X509证书
     * @return resource
     */
    public static function x509Read($x509certdata)
    {
        return openssl_x509_read($x509certdata);
    }
}
