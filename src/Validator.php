<?php


namespace fize\security;

use Closure;
use Exception;

/**
 * 验证器
 */
class Validator
{
    /**
     * @var array 规则定义
     */
    protected $rules = [];

    /**
     * @var array 字段命名定义
     */
    protected $names = [];

    /**
     * @var array 验证器信息定义
     */
    protected $validates = [];

    /**
     * @var array 信息定义
     */
    protected $messages = [];

    /**
     * @var array 场景定义
     */
    protected $scenes = [];

    /**
     * @var string 指定场景
     */
    protected $scene = null;

    /**
     * @var bool 是否批量验证
     */
    protected $batch = false;

    /**
     * @var array 捕获错误
     */
    protected $errors = [];

    /**
     * @var array 待验证数据
     */
    protected $data = [];

    /**
     * @var array 场景规则重定义
     */
    protected $sceneRules = [];

    /**
     * @var array 场景字段命名重定义
     */
    protected $sceneNames = [];

    /**
     * @var array 场景信息重定义
     */
    protected $sceneMessages = [];

    /**
     * @var array 场景待验证数据重定义
     */
    protected $sceneDatas = [];

    /**
     * 构造
     *
     * 在此定义一些相对复杂的配置
     */
    public function __construct()
    {
        $this->validates = [
            'regex'       => '不符合指定规则',
            'filter'      => '不符合指定规则',
            'isset'       => '必须赋值',
            'empty'       => '必须为空',
            'notEmpty'    => '不能为空',
            'null'        => '必须为 NULL',
            'notNull'     => '不能为 NULL',
            'number'      => '必须纯数字',
            'int'         => '必须为整数',
            'float'       => '必须为浮点数',
            'bool'        => '必须为布尔值',
            'email'       => '不是有效的邮箱地址',
            'array'       => '必须是数组',
            'date'        => '必须使用日期格式 %s',
            'alpha'       => '必须纯字母',
            'alphaNum'    => '必须为字母或数字',
            'alphaDash'   => '只允许字母和数字，下划线_及破折号 -',
            'chs'         => '必须为汉字',
            'chsAlpha'    => '必须为汉字或字母',
            'chsAlphaNum' => '只能是汉字、字母和数字',
            'chsDash'     => '只能是汉字、字母、数字和下划线 _ 及破折号 -',
            'cntrl'       => '只能是控制字符（换行、缩进、空格）',
            'graph'       => '只能是可打印字符（空格除外）',
            'print'       => '只能是可打印字符（包括空格）',
            'lower'       => '只能是小写字符',
            'upper'       => '只能是大写字符',
            'space'       => '只能是空白字符（包括缩进，垂直制表符，换行符，回车和换页字符）',
            'xdigit'      => '只能是十六进制字符串',
            'dnsrr'       => '不是有效的域名或者 IP',
            'url'         => '不是有效的 URL 地址',
            'ip'          => '不是有效的 IP 地址',
            'mobile'      => '不是有效的手机号码',
            'idCard'      => '不是有效的身份证格式',
            'macAddr'     => '不是有效的 MAC 地址',
            'zip'         => '不是有效的邮政编码',
            'in'          => '不在指定数组内',
            'notIn'       => '不允许的数值',
            'between'     => '只能在 %s - %s 之间',
            'notBetween'  => '只能在 %s - %s 之外',
            'length'      => '长度必须在 %s - %s 之间',
            'maxLength'   => '最大长度不能大于 %s',
            'minLength'   => '最小长度不能小于 %s',
            'after'       => '必须在 %s 之后',
            'before'      => '必须在 %s 之前',
            'expire'      => '必须在 %s - %s 之间',
            'inIp'        => '不允许的IP访问',
            'confirm'     => '两次输入不一致',
            'different'   => '两次输入不能相同',
            'fieldEgt'    => '必须大于等于 %s',
            'fieldGt'     => '必须大于 %s',
            'fieldElt'    => '必须小于等于 %s',
            'fieldLt'     => '必须小于 %s',
            'eq'          => '必须等于 %s',
            'neq'         => '不能等于 %s',
            'egt'         => '必须大于等于 %s',
            'gt'          => '必须大于 %s',
            'elt'         => '必须小于等于 %s',
            'lt'          => '必须小于 %s',
            'file'        => '必须为文件',
            'image'       => '必须为图片'
        ];
    }

    /**
     * 规则定义
     * @param array $rules 规则
     */
    public function rules(array $rules)
    {
        $this->rules = $rules;
    }

    /**
     * 命名定义
     * @param array $names 命名
     */
    public function names(array $names)
    {
        $this->names = $names;
    }

    /**
     * 添加验证器信息定义
     * @param string $validate 验证器名称
     * @param string $description 信息描述
     */
    public function validate($validate, $description)
    {
        $this->validates[$validate] = $description;
    }

    /**
     * 信息定义
     * @param array $messages 信息
     */
    public function messages(array $messages)
    {
        $this->messages = $messages;
    }

    /**
     * 场景定义
     * @param array $scenes 场景
     */
    public function scenes(array $scenes)
    {
        $this->scenes = $scenes;
    }

    /**
     * 是否有指定场景
     * @param string $scene 场景
     * @return bool
     */
    public function hasScene($scene)
    {
        return isset($this->scenes[$scene]);
    }

    /**
     * 场景指定
     * @param string $scene 场景
     */
    public function scene($scene)
    {
        $this->scene = $scene;
    }

    /**
     * 设置是否批量验证
     * @param bool $batch 是否批量验证
     */
    public function batch($batch)
    {
        $this->batch = $batch;
    }

    /**
     * 设置待验证数据
     *
     * 该方法不会覆盖由 sceneDatas 方法定义的数据
     * @param array $data 待验证数据
     */
    public function data(array $data)
    {
        $this->data = $data;
    }

    /**
     * 设置场景规则重定义
     * @param string $scene 场景
     * @param array $rules 规则
     */
    public function sceneRules($scene, array $rules)
    {
        $this->sceneRules[$scene] = $rules;
    }

    /**
     * 设置场景字段命名重定义
     * @param string $scene 场景
     * @param array $names 字段命名
     */
    public function sceneNames($scene, array $names)
    {
        $this->sceneNames[$scene] = $names;
    }

    /**
     * 设置场景信息重定义
     * @param string $scene 场景
     * @param array $messages 场景信息
     */
    public function sceneMessages($scene, array $messages)
    {
        $this->sceneMessages[$scene] = $messages;
    }

    /**
     * 设置场景待验证数据重定义
     * @param string $scene 场景
     * @param array $data 待验证数据
     */
    public function sceneDatas($scene, array $data)
    {
        $this->sceneDatas[$scene] = $data;
    }

    /**
     * 验证数据
     *
     * 如果启用批量验证，则失败时返回值为错误数组，否则为错误信息
     * @param array $data 待验证数据
     * @return bool|string|array 成功返回 true，失败返回失败信息
     */
    public function check(array $data = null)
    {
        if(is_null($data)) {
            if ($this->scene && isset($this->sceneDatas[$this->scene])) {
                $data = $this->sceneDatas[$this->scene];
            } else {
                $data = $this->data;
            }
        }
        $rules = $this->getFinalRules();
        if(!$rules) {
            return true;
        }
        $check = true;
        foreach (array_keys($data) as $field) {
            if(isset($rules[$field])) {
                $check = $check && $this->checkField($field, $rules[$field], $data);
                if (!$check && $this->batch == false) {
                    return $this->errors[0];
                }
            }
        }
        if (!$check) {
            return $this->errors;
        }
        return true;
    }

    /**
     * 取得最后实际使用的规则
     * @return array
     */
    protected function getFinalRules()
    {
        $rules = $this->rules;

        if ($this->scene && isset($this->sceneRules[$this->scene])) {
            $rules = array_merge($rules, $this->sceneRules[$this->scene]);
        }

        if ($this->scene && isset($this->scenes[$this->scene])) {
            foreach (array_keys($rules) as $key) {
                if (!in_array($key, $this->scenes[$this->scene])) {
                    unset($rules[$key]);
                }
            }
        }
        return $rules;
    }

    /**
     * 验证单个字段规则
     * @param string $field 字段名
     * @param array $rules 规则
     * @param array $data 数据
     * @return bool 成功返回 true，失败返回 false
     */
    protected function checkField($field, array $rules, array $data)
    {
        if (!is_array($rules)) {  //单个条件的简易写法
            $rules = [$rules];
        }

        $names = $this->names;
        if ($this->scene && isset($this->sceneNames[$this->scene])) {
            $names = array_merge($names, $this->sceneNames[$this->scene]);
        }
        $name = isset($names[$field]) ? $names[$field] : $field;

        $messages = $this->messages;
        if ($this->scene && isset($this->sceneMessages[$this->scene])) {
            $messages = array_merge($messages, $this->sceneMessages[$this->scene]);
        }
        $message = isset($messages[$field]) ? $messages[$field] : null;

        $check = true;
        foreach ($rules as $key => $value) {
            list($result, $validate, $parameters) = $this->validateItem($key, $value, $data, $field);
            $check = $check && $result;
            if (!$result) {
                if ($this->batch || empty($this->errors)) {
                    if (isset($message[$validate])) {
                        $errmsg = sprintf($message[$validate], ...$parameters);
                    } elseif (is_string($message)) {
                        $errmsg = sprintf($message, ...$parameters);
                    } else {
                        if (is_string($validate) && isset($this->validates[$validate])) {
                            $errmsg = $name . $this->validates[$validate];
                        } else {
                            $errmsg = "field error: {$name}";
                        }
                        $errmsg = sprintf($errmsg, ...$parameters);
                    }
                    $this->errors[] = $errmsg;
                }
            }
        }
        return $check;
    }

    /**
     * 获取验证结果
     * @param mixed $key 规则键名
     * @param mixed $value 规则键值
     * @param array $data 数据
     * @param string $field 字段名
     * @return array
     */
    protected function validateItem($key, $value, array $data, $field)
    {
        $validate = $key;
        $parameters = [];
        $field_value = isset($data[$field]) ? $data[$field] : null;

        if (is_int($key)) {  //数字键名则键值做为方法名
            $validate = $value;
        } else {
            if (is_array($value)) {
                $parameters = $value;
            } else {
                $parameters = [$value];
            }
        }

        $fun_parameters = [];
        $fun_parameters[] = $field_value;
        $fun_parameters = array_merge($fun_parameters, $parameters);
        $fun_parameters[] = $data;
        $fun_parameters[] = $field;

        if ($validate instanceof Closure) { //闭包
            $result = $validate($field_value, $data, $field);
        } elseif (method_exists(static::class, $validate)) { //自定义方法
            $result = call_user_func_array([static::class, $validate], $fun_parameters);
        } elseif (method_exists(Validate::class, $validate)) {  //内置验证
            if ($validate == 'isset') {
                $result = Validate::isset($field, $data);
            } else {
                $result = call_user_func_array([Validate::class, $validate], $fun_parameters);
            }
        } elseif (function_exists($validate)) {  //函数
            $result = call_user_func_array($validate, $fun_parameters);
        } else {
            throw new Exception("Validate Rule `{$validate}` in `{$field}` not found!");
        }

        return [$result, $validate, $parameters];
    }
}