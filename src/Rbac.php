<?php

namespace fize\safe;

/**
 * 基于角色的数据库方式验证类
 */
class Rbac
{

    /**
     * 获取要判断的用户记录
     * @param mixed $map 查询条件
     * @param string $table 用户表名
     * @return mixed
     */
    static public function authenticate($map, $table = '')
    {
        if (empty($table)) $table = C('RBAC_USER_TABLE');
        return M()->table($table)->where($map)->find();
    }

    /**
     * 取得用户的所有权限数组，适用于三级模型
     * @param int $uid 用户ID
     * @return array
     */
    static public function getAccessList($uid)
    {
        $db = M();
        $table = array('role' => C('RBAC_ROLE_TABLE'), 'user' => C('RBAC_USER_TABLE'), 'access' => C('RBAC_ACCESS_TABLE'), 'node' => C('RBAC_NODE_TABLE'));
        $sql = "select node.id,node.name from " .
            $table['role'] . " as role," .
            $table['user'] . " as user," .
            $table['access'] . " as access ," .
            $table['node'] . " as node " .
            "where user.user_id='{$uid}' and user.role_id=role.id and ( access.role_id=role.id  or (access.role_id=role.pid and role.pid!=0 ) ) and role.status=1 and access.node_id=node.id and node.level=1 and node.status=1";
        $apps = $db->query($sql);
        $access = array();
        foreach ($apps as $key => $app) {
            $appId = $app['id'];
            $appName = $app['name'];
            // 读取项目的模块权限
            $access[strtoupper($appName)] = array();
            $sql = "select node.id,node.name from " .
                $table['role'] . " as role," .
                $table['user'] . " as user," .
                $table['access'] . " as access ," .
                $table['node'] . " as node " .
                "where user.user_id='{$uid}' and user.role_id=role.id and ( access.role_id=role.id  or (access.role_id=role.pid and role.pid!=0 ) ) and role.status=1 and access.node_id=node.id and node.level=2 and node.pid={$appId} and node.status=1";
            $modules = $db->query($sql);
            // 判断是否存在公共模块的权限
            $publicAction = array();
            foreach ($modules as $key => $module) {
                $moduleId = $module['id'];
                $moduleName = $module['name'];
                if ('PUBLIC' == strtoupper($moduleName)) {
                    $sql = "select node.id,node.name from " .
                        $table['role'] . " as role," .
                        $table['user'] . " as user," .
                        $table['access'] . " as access ," .
                        $table['node'] . " as node " .
                        "where user.user_id='{$uid}' and user.role_id=role.id and ( access.role_id=role.id  or (access.role_id=role.pid and role.pid!=0 ) ) and role.status=1 and access.node_id=node.id and node.level=3 and node.pid={$moduleId} and node.status=1";
                    $rs = $db->query($sql);
                    foreach ($rs as $a) {
                        $publicAction[$a['name']] = $a['id'];
                    }
                    unset($modules[$key]);
                    break;
                }
            }
            // 依次读取模块的操作权限
            foreach ($modules as $key => $module) {
                $moduleId = $module['id'];
                $moduleName = $module['name'];
                $sql = "select node.id,node.name from " .
                    $table['role'] . " as role," .
                    $table['user'] . " as user," .
                    $table['access'] . " as access ," .
                    $table['node'] . " as node " .
                    "where user.user_id='{$uid}' and user.role_id=role.id and ( access.role_id=role.id  or (access.role_id=role.pid and role.pid!=0 ) ) and role.status=1 and access.node_id=node.id and node.level=3 and node.pid={$moduleId} and node.status=1";
                $rs = $db->query($sql);
                $action = array();
                foreach ($rs as $a) {
                    $action[$a['name']] = $a['id'];
                }
                // 和公共模块的操作权限合并
                $action += $publicAction;
                $access[strtoupper($appName)][strtoupper($moduleName)] = array_change_key_case($action, CASE_UPPER);
            }
        }
        return $access;
    }

    /**
     * 检测用户权限的方法,并保存到Session中
     * @param int $uid 用户UID
     * @return string
     */
    static function saveAccessList($uid = null)
    {
        if (null === $uid) $uid = $_SESSION[C('RBAC_USER_AUTH_KEY')];
        // 如果使用普通权限模式，保存当前用户的访问权限列表
        // 对管理员开发所有权限
        if (C('RBAC_AUTH_TYPE') != 2 && !$_SESSION[C('RBAC_SUPER_ADMIN_BOOL_KEY')]) $_SESSION[C('RBAC_ACCESS_AUTH_KEY')] = RBAC::getAccessList($uid);
        return;
    }

    /**
     * 以同类角色获取权限数组
     * @param int $p_roleId 角色ID
     * @param int $p_userId 用户ID
     * @return array
     */
    static function roleAccessList($p_roleId, $p_userId)
    {
        $cache_key = C('RBAC_ROLE_CACHE_PREFIX') . $p_roleId;
        if (F($cache_key)) {
            return F($cache_key);
        } else {
            $access_list = self::getAccessList($p_userId);
            F($cache_key, $access_list);
            return $access_list;
        }
    }

    /**
     * 检查当前是否需要认证
     * @return boolean
     */
    static function checkAccess()
    {
        //如果项目要求认证，并且当前模块需要认证，则进行权限认证
        if (C('RBAC_AUTH_ON')) {
            $_module = array();
            $_action = array();
            if ("" != C('RBAC_REQUIRE_AUTH_MODULE')) {
                //需要认证的模块
                $_module['yes'] = explode(',', strtoupper(C('RBAC_REQUIRE_AUTH_MODULE')));
            } else {
                //无需认证的模块
                $_module['no'] = explode(',', strtoupper(C('RBAC_NOT_AUTH_MODULE')));
            }
            //检查当前模块是否需要认证
            if ((!empty($_module['no']) && !in_array(strtoupper(MODULE_NAME), $_module['no'])) || (!empty($_module['yes']) && in_array(strtoupper(MODULE_NAME), $_module['yes']))) {
                if ("" != C('RBAC_REQUIRE_AUTH_ACTION')) {
                    //需要认证的操作
                    $_action['yes'] = explode(',', strtoupper(C('RBAC_REQUIRE_AUTH_ACTION')));
                } else {
                    //无需认证的操作
                    $_action['no'] = explode(',', strtoupper(C('RBAC_NOT_AUTH_ACTION')));
                }
                //检查当前操作是否需要认证
                if ((!empty($_action['no']) && !in_array(strtoupper(ACTION_NAME), $_action['no'])) || (!empty($_action['yes']) && in_array(strtoupper(ACTION_NAME), $_action['yes']))) {
                    return true;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }
        return false;
    }

    /**
     * 检查是否运行匿名用户登录
     * @return boolean
     */
    static public function checkGuest()
    {
        //检查当前操作是否需要认证
        if (RBAC::checkAccess()) {
            //检查认证识别号
            if (!$_SESSION[C('RBAC_USER_AUTH_KEY')]) {
                if (C('RBAC_GUEST_ON')) {
                    // 开启游客授权访问
                    if (!isset($_SESSION[C('RBAC_ACCESS_AUTH_KEY')]))
                        // 保存游客权限
                        RBAC::saveAccessList(C('GUEST_AUTH_ID'));
                } else {
                    // 禁止游客访问跳转到认证网关
                    redirect(PHP_FILE . C('RBAC_AUTH_GATEWAY'));
                }
            }
        }
        return true;
    }

    /**
     * 判断用户是否超级管理员
     * @param string $p_val 用户表示字符串
     * @return boolean
     */
    static public function checkSuperAdmin($p_val)
    {
        if (C('RBAC_SUPER_ADMIN') === false) {
            return false;
        }
        if ($p_val === C('RBAC_SUPER_ADMIN')) {
            $_SESSION[C('RBAC_SUPER_ADMIN_BOOL_KEY')] = true;
        } else {
            $_SESSION[C('RBAC_SUPER_ADMIN_BOOL_KEY')] = false;
        }
    }

    /**
     * 权限认证的过滤器方法
     * @param string $groupName 分组名
     * @param string $moduleName 模块名
     * @param string $actionName 操作名
     * @return boolean
     */
    static public function AccessDecision($groupName = GROUP_NAME, $moduleName = MODULE_NAME, $actionName = ACTION_NAME)
    {
        //检查是否需要认证
        if (RBAC::checkAccess()) {
            if (isset($_SESSION[C('RBAC_SUPER_ADMIN_BOOL_KEY')]) && $_SESSION[C('RBAC_SUPER_ADMIN_BOOL_KEY')] === true) {
                //管理员无需认证
                return true;
            } else {
                $groupName = strtoupper($groupName);
                $moduleName = strtoupper($moduleName);
                $actionName = strtoupper($actionName);
                //存在认证识别号，则进行进一步的访问决策
                $accessGuid = md5($groupName . $moduleName . $actionName);
                if (C('RBAC_AUTH_TYPE') == 2) {
                    //加强验证和即时验证模式 更加安全 后台权限修改可以即时生效
                    //通过数据库进行访问检查
                    $accessList = RBAC::getAccessList($_SESSION[C('RBAC_USER_AUTH_KEY')]);
                } else {
                    // 如果是管理员或者当前操作已经认证过，无需再次认证
                    if (isset($_SESSION[$accessGuid]) && $_SESSION[$accessGuid]) {
                        return true;
                    }
                    //登录验证模式，比较登录后保存的权限访问列表
                    $accessList = $_SESSION[C('RBAC_ACCESS_AUTH_KEY')];
                }
                if (!isset($accessList[$groupName][$moduleName][$actionName])) {

                    log_app(onlineip() . "越权访问:" . $groupName . '|' . $moduleName . "|" . $actionName);

                    $_SESSION[$accessGuid] = false;
                    return false;
                } else {
                    $_SESSION[$accessGuid] = true;
                }
            }
        }
        return true;
    }

    /**
     * 判断普通RBAC是否已进行了SESSION缓存
     * @return bool
     */
    static public function isReady()
    {
        return isset($_SESSION[C('RBAC_ACCESS_AUTH_KEY')]) && !empty($_SESSION[C('RBAC_ACCESS_AUTH_KEY')]);
    }

    /**
     * 检查RBAC
     * @param array $p_map 用户条件MAP
     * @param string $p_ident 用户标识列名，用于判别超级用户
     * @return mixed
     */
    static public function checkRBAC($p_map, $p_ident)
    {
        $t_out = array();
        //先检测RBAC状态,未启动时进行设置
        if (!self::isReady()) {
            $authInfo = RBAC::authenticate($p_map);
            if ($authInfo) {
                $_SESSION[C('RBAC_USER_AUTH_KEY')] = $authInfo['user_id'];
                //超级管理员
                self::checkSuperAdmin($authInfo[$p_ident]);
                // 缓存访问权限
                //RBAC::saveAccessList();
                // 通过角色缓存访问权限
                $t_access = self::roleAccessList($authInfo['role_id'], $authInfo['user_id']);
                $_SESSION[C('RBAC_ACCESS_AUTH_KEY')] = $t_access;
            } else {
                $t_out = array('errcode' => 101, 'errmsg' => '无效用户');
            }
        }
        if (!self::AccessDecision()) {
            //检查网关
            $t_gate = C('RBAC_AUTH_GATEWAY');
            if ($t_gate && !empty($t_gate)) {
                //跳转到认证网关
                redirect(U($t_gate));
            }
            // 没有权限 跳转到指定错误URL
            $t_rpage = C('RBAC_ERROR_PAGE');
            if ($t_rpage && !empty($t_rpage)) {
                // 定义权限错误页面
                redirect($t_rpage);
            } else {
                if (C('RBAC_GUEST_ON')) {
                    $t_out = array('errcode' => 0, 'errmsg' => '匿名用户', 'uid' => C('RBAC_GUEST_ID'));
                } else {
                    $t_out = array('errcode' => 102, 'errmsg' => '您无权登录此页面');
                }
            }
        }
        if (!empty($t_out)) {
            return $t_out;
        }
    }

    /**
     * 适用于AJAX的RBAC检测
     */
    static public function ajaxRBAC()
    {
        $t_out = array();
        if (self::isReady()) {
            if (self::AccessDecision()) {
                $t_out = array('errcode' => 0, 'errmsg' => 'RBAC检测成功');
            } else {
                $t_out = array('errcode' => 102, 'errmsg' => '您无权登录此页面');
            }
        } else {
            $t_out = array('errcode' => 103, 'errmsg' => 'RBAC超时，请重新登录');
        }
    }

    /**
     * 重设RBAC权限
     */
    static public function reSet()
    {
        unset($_SESSION[C('RBAC_ACCESS_AUTH_KEY')]);
        unset($_SESSION[C('RBAC_SUPER_ADMIN')]);
    }
}