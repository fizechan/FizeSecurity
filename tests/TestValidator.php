<?php

namespace Tests;

use Fize\Security\Validator;
use PHPUnit\Framework\TestCase;

class TestValidator extends TestCase
{

    public function testCheck()
    {
        $validator = new AuthAdmin();
        $validator->scene('add');

        $data = [
            'username'         => '123456',
            'email'            => 'test2@test.com',
            'nickname'         => 'FizeChan',
            'password'         => '123456',
            'password_confirm' => '123456',
        ];

        $result = $validator->check($data);
        var_dump($result);
    }

    public function testLogin()
    {
        $validator = new AuthAdmin();
        $validator->scene('login');

        $data = [
            'username'  => '123456',
            'password'  => '123456',
            'captcha'   => '100',
            '__token__' => '1234567',
        ];

        $result = $validator->check($data);
        var_dump($result);
    }
}

class AuthAdmin extends Validator
{

    public function __construct()
    {
        parent::__construct();

        $this->validates['isCaptcha'] = '只能是 %s 或 %s';
        $this->validates['unique'] = '已被使用';


        $this->rules = [
            'username' => [
                'isRequire',
                'maxLength' => 50,
                'unique'
            ],
            'nickname' => 'notEmpty',
            'password' => [
                'notEmpty',
                'confirm' => 'password_confirm'
            ],
            'email'    => [
                'notEmpty',
                'email',
                'uniqueEmail'
            ],
            'captcha'  => [
                'notEmpty',
                'isCaptcha' => [100, 200]
            ],
        ];

        $this->names = [
            'username'  => '用户名',
            'nickname'  => '昵称',
            'password'  => '密码',
            'email'     => '邮箱',
            'captcha'   => '验证码',
            '__token__' => 'TOKEN'
        ];

        $this->messages = [
            'username' => [
                'unique' => '该用户名已被使用'
            ],
            'email'    => [
                'uniqueEmail' => '该邮箱已被注册'
            ],
            'password' => [
                'confirm' => '两次密码不一致'
            ],
            '__token__' => 'TOKEN 错误'
        ];

        $this->sceneRules = [
            'login' => [
                'username'  => [  //重新定义
                    'isset',
                    'maxLength' => 50,
                ],
                'password'  => 'notEmpty',
                'captcha'   => [
                    'isCaptcha' => [100, 200]
                ],
                '__token__' => function ($value) {
                    if ($value == '123456') {
                        return true;
                    }
                    return false;
                }
            ]
        ];

        $this->sceneNames = [
            'login' => [
                'username' => '账号',
            ]
        ];

        $this->sceneMessages = [
            'login' => [
                'username' => [
                    'unique' => '账号已被使用'
                ],
            ]
        ];

        $this->scenes = [
            'add'   => ['username', 'email', 'nickname', 'password'],
            'edit'  => ['username', 'email', 'nickname'],
            'login' => ['username', 'password', 'captcha', '__token__'],
        ];
    }

    /**
     * 自定义验证器
     * @param $value
     * @param $data
     * @param $field
     * @return bool
     * @noinspection PhpUnusedParameterInspection
     */
    public static function isRequire($value, $data, $field)
    {
        return isset($data[$field]);
    }

    /**
     * 自定义验证器
     * @param $value
     * @return bool
     */
    public static function unique($value)
    {
        $arr = [1, 2, 3];
        return !in_array($value, $arr);
    }

    /**
     * 自定义验证器
     * @param $value
     * @return bool
     */
    public static function uniqueEmail($value)
    {
        $arr = ['test@test.com'];
        return !in_array($value, $arr);
    }

    /**
     * 自定义验证器
     * @param $value
     * @param $param1
     * @param $param2
     * @return bool
     */
    public static function isCaptcha($value, $param1, $param2)
    {
        $bool1 = $value == $param1;
        $bool2 = $value == $param2;
        return $bool1 || $bool2;
    }
}
