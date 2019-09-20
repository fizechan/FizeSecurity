<?php

namespace fize\security;

use Exception;

/**
 * 谷歌二次验证
 * @todo 非底层功能，待转移到其他位置
 * @notice 待移动到其他位置
 * @package fize\security
 */
class GoogleAuthenticator
{

    /**
     * @var int 验证码长度
     */
    protected $_codeLength = 6;

    /**
     * 创建密钥
     * @param int $secretLength 密钥长度
     * @return string
     * @throws Exception
     */
    public function createSecret($secretLength = 16)
    {
        $validChars = $this->_getBase32LookupTable();

        // Valid secret lengths are 80 to 640 bits
        if ($secretLength < 16 || $secretLength > 128) {
            throw new Exception('Bad secret length');
        }
        $secret = '';
        $rnd = random_bytes($secretLength);
        for ($i = 0; $i < $secretLength; ++$i) {
            $secret .= $validChars[ord($rnd[$i]) & 31];
        }

        return $secret;
    }

    /**
     * 根据密钥取得验证码
     * @param string $secret 密钥
     * @param int $timeSlice 指定时间戳，不指定为当前时间
     * @return string
     */
    public function getCode($secret, $timeSlice = null)
    {
        if ($timeSlice === null) {
            $timeSlice = floor(time() / 30);
        }

        $secretkey = $this->_base32Decode($secret);

        // Pack time into binary string
        $time = chr(0) . chr(0) . chr(0) . chr(0) . pack('N*', $timeSlice);
        // Hash it with users secret key
        $hm = hash_hmac('SHA1', $time, $secretkey, true);
        // Use last nipple of result as index/offset
        $offset = ord(substr($hm, -1)) & 0x0F;
        // grab 4 bytes of the result
        $hashpart = substr($hm, $offset, 4);

        // Unpak binary value
        $value = unpack('N', $hashpart);
        $value = $value[1];
        // Only 32 bits
        $value = $value & 0x7FFFFFFF;

        $modulo = pow(10, $this->_codeLength);

        return str_pad($value % $modulo, $this->_codeLength, '0', STR_PAD_LEFT);
    }

    /**
     * QR-Code URL
     * @param $name
     * @param $secret
     * @param null $title
     * @param array $params
     * @return string
     */
    public function getQRCodeGoogleUrl($name, $secret, $title = null, $params = array())
    {
        $width = !empty($params['width']) && (int)$params['width'] > 0 ? (int)$params['width'] : 200;
        $height = !empty($params['height']) && (int)$params['height'] > 0 ? (int)$params['height'] : 200;
        $level = !empty($params['level']) && array_search($params['level'], array('L', 'M', 'Q', 'H')) !== false ? $params['level'] : 'M';

        $urlencoded = urlencode('otpauth://totp/' . $name . '?secret=' . $secret . '');
        if (isset($title)) {
            $urlencoded .= urlencode('&issuer=' . urlencode($title));
        }

        return 'https://chart.googleapis.com/chart?chs=' . $width . 'x' . $height . '&chld=' . $level . '|0&cht=qr&chl=' . $urlencoded . '';
    }

    /**
     * 验证验证码
     * @param string $secret 密钥
     * @param string $code 验证码
     * @param int $discrepancy 验证误差跨度，越小安全性越高，验证码有效时间越短
     * @param int $currentTimeSlice 指定时间戳
     * @return bool
     */
    public function verifyCode($secret, $code, $discrepancy = 1, $currentTimeSlice = null)
    {
        if ($currentTimeSlice === null) {
            $currentTimeSlice = floor(time() / 30);
        }

        if (strlen($code) != 6) {
            return false;
        }

        for ($i = -$discrepancy; $i <= $discrepancy; ++$i) {
            $calculatedCode = $this->getCode($secret, $currentTimeSlice + $i);
            if (hash_equals($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    /**
     * 设置验证码长度
     * @param int $length 长度
     * @return $this
     */
    public function setCodeLength($length)
    {
        $this->_codeLength = $length;
        return $this;
    }

    /**
     * 解密base32
     * @param string $secret
     * @return string
     * @throws Exception
     */
    protected function _base32Decode($secret)
    {
        if (empty($secret)) {
            return '';
        }

        $base32chars = $this->_getBase32LookupTable();
        $base32charsFlipped = array_flip($base32chars);

        $paddingCharCount = substr_count($secret, $base32chars[32]);
        $allowedValues = [6, 4, 3, 1, 0];
        if (!in_array($paddingCharCount, $allowedValues)) {
            throw new Exception('Bad base32 decode');
        }
        for ($i = 0; $i < 4; ++$i) {
            if ($paddingCharCount == $allowedValues[$i] && substr($secret, -($allowedValues[$i])) != str_repeat($base32chars[32], $allowedValues[$i])) {
                throw new Exception('Bad base32 decode');
            }
        }
        $secret = str_replace('=', '', $secret);
        $secret = str_split($secret);
        $binaryString = '';
        for ($i = 0; $i < count($secret); $i = $i + 8) {
            $x = '';
            if (!in_array($secret[$i], $base32chars)) {
                throw new Exception('Bad base32 decode');
            }
            for ($j = 0; $j < 8; ++$j) {
                $x .= str_pad(base_convert($base32charsFlipped[$secret[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
            }
            $eightBits = str_split($x, 8);
            for ($z = 0; $z < count($eightBits); ++$z) {
                $binaryString .= (($y = chr(base_convert($eightBits[$z], 2, 10))) || ord($y) == 48) ? $y : '';
            }
        }

        return $binaryString;
    }

    /**
     * base32可用字符数组
     * @return array
     */
    protected function _getBase32LookupTable()
    {
        return [
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
            'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
            '=',  // padding char
        ];
    }
}
