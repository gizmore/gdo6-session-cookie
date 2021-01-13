<?php
namespace GDO\Session;

use GDO\Core\Application;
use GDO\User\GDO_User;
use GDO\Util\Math;
use GDO\Util\AES;
use GDO\Core\Website;
use GDO\Net\GDT_IP;

/**
 * AES-Cookie driven Session handler.
 * The code is a bit ugly because i mimiced the GDO interface badly.
 * @TODO cleanup session code in other modules
 *
 * @author gizmore
 * @version 6.11
 * @since 3.00
 */
class GDO_Session
{
    const DUMMY_COOKIE_CONTENT = 'GDO_like_16_byte';
    
    public static $INSTANCE;
    public static $STARTED = false;
    
    private static $COOKIE_NAME = 'GDO6';
    private static $COOKIE_DOMAIN = 'localhost';
    private static $COOKIE_JS = true;
    private static $COOKIE_HTTPS = true;
    private static $COOKIE_SECONDS = 72600;
    
    public static function isDB() { return false; }
    
    public function getID()
    {
        return $this->getVar('sess_id');
    }
    
    public static function blank()
    {
        self::$INSTANCE = new self();
        GDO_User::setCurrent(GDO_User::ghost());
        return self::$INSTANCE;
    }
    
    // 	public function getToken() { return $this->getVar('sess_token'); }
    public function getUser()
    {
        if ($uid = $this->getVar('sess_user'))
        {
            if ($user = GDO_User::table()->find($uid, false))
            {
                return $user;
            }
            $this->setDummyCookie(); # somethings wrong in db!
        }
    }
    public function getIP() { return $this->getVar('sess_ip'); }
    public function getTime() { return $this->getVar('sess_time'); }
    public function getData() { return $this->getVar('sess_data'); }
    public function getLastURL() { return $this->getVar('sess_last_url'); }
    
    public function setVar($key, $value)
    {
        if ($key === 'sess_data')
        {
            $this->cookieData = $value;
            $this->cookieChanged = true;
        }
        else
        {
            self::set($key, $value);
        }
    }
    
    public function getVar($key)
    {
        return self::get($key);
    }
    
    public function save()
    {
        return $this;
    }
    
    public $cookieData = [];
    private $cookieChanged = false;
    
    /**
     * Get current user or ghost.
     * @return GDO_User
     */
    public static function user()
    {
        if ( (!($session = self::instance())) ||
            (!($user = $session->getUser())) )
        {
            return GDO_User::ghost();
        }
        return $user;
    }
    
    /**
     * @return self
     */
    public static function instance()
    {
        if ( (!self::$INSTANCE) && (!self::$STARTED) )
        {
            self::$INSTANCE = self::start();
            self::$STARTED = true; # only one try
        }
        return self::$INSTANCE;
    }
    
    public static function reset()
    {
        self::$INSTANCE = null;
        self::$STARTED = false;
    }
    
    public static function init($cookieName='GDO6', $domain='localhost', $seconds=-1, $httpOnly=true, $https = false)
    {
        self::$COOKIE_NAME = $cookieName;
        self::$COOKIE_DOMAIN = $domain;
        self::$COOKIE_SECONDS = Math::clamp($seconds, -1, 1234567);
        self::$COOKIE_JS = !$httpOnly;
        self::$COOKIE_HTTPS = $https;
    }
    
    ######################
    ### Get/Set/Remove ###
    ######################
    public static function get($key, $initial=null)
    {
        $session = self::instance();
        $data = $session ? $session->cookieData : [];
        return isset($data[$key]) ? $data[$key] : $initial;
    }
    
    public static function set($key, $value)
    {
        if ($session = self::instance())
        {
            if (@$session->cookieData[$key] !== $value)
            {
                $session->cookieChanged = true;
                $session->cookieData[$key] = $value;
            }
        }
    }
    
    public static function remove($key)
    {
        if ($session = self::instance())
        {
            $session->cookieChanged = true;
            unset($session->cookieData[$key]);
        }
    }
    
    public static function commit()
    {
        if (self::$INSTANCE)
        {
            self::$INSTANCE->setCookie();
        }
    }
    
    public static function getCookieValue()
    {
        return isset($_COOKIE[self::$COOKIE_NAME]) ? (string)$_COOKIE[self::$COOKIE_NAME] : null;
    }
    
    /**
     * Start and get user session
     * @param string $cookieval
     * @param string $cookieip
     * @return self
     */
    private static function start($cookieValue=true, $cookieIP=true)
    {
        # Parse cookie value
        if ($cookieValue === true)
        {
            if (!isset($_COOKIE[self::$COOKIE_NAME]))
            {
                self::setDummyCookie();
                return false;
            }
            $cookieValue = (string)$_COOKIE[self::$COOKIE_NAME];
        }
        
        # Special first cookie
        if ($cookieValue === self::DUMMY_COOKIE_CONTENT)
        {
            $session = self::createSession($cookieIP);
        }
        # Try to reload
        elseif ($session = self::reloadCookie($cookieValue, $cookieIP))
        {
            if ( (!$session->ipCheck()) ||
                 (!$session->timeCheck()) )
            {
                self::setDummyCookie();
                return false;
            }
        }
        # Set special first dummy cookie
        else
        {
            self::setDummyCookie();
            return false;
        }
        
        return $session;
    }
    
    public static function reloadCookie($cookieValue)
    {
        if ($decrypted = AES::decryptIV($cookieValue, GWF_SALT))
        {
            if ($decoded = zlib_decode($decrypted))
            {
                $sess = new self();
                if ($sess->cookieData = json_decode(rtrim($decoded, "\x00"), true))
                {
                    self::$INSTANCE = $sess;
                    //         		GDO_User::$CURRENT = $sess->getUser();
                    return $sess;
                }
                else
                {
                    self::setDummyCookie();
                }
            }
        }
        return false;
    }
    
    public function ipCheck()
    {
        if ($ip = $this->getIP())
        {
            return $ip === GDT_IP::current();
        }
        return true;
    }
    
    public function timeCheck()
    {
        if ($time = $this->getTime())
        {
            if ( ($time + GWF_SESS_TIME) < Application::$TIME)
            {
                return false;
            }
        }
        return true;
    }
    
    private function setCookie()
    {
        if ( (!Application::instance()->isCLI()) && (!Application::instance()->isInstall()) )
        {
            if ($this->cookieChanged)
            {
// 		        Logger::logDebug(json_encode($this->cookieData));
                if (!setcookie(self::$COOKIE_NAME, $this->cookieContent(), Application::$TIME + self::$COOKIE_SECONDS, '/', self::$COOKIE_DOMAIN, self::cookieSecure(), !self::$COOKIE_JS))
                {
                    Website::error('err_set_cookie');
                    die('ERR');
                }
            }
        }
    }
    
    public function cookieContent()
    {
        if (!$this->cookieData)
        {
            $this->cookieData = [];
        }
        $this->cookieData['sess_time'] = Application::$TIME;
        $json = json_encode($this->cookieData);
//         Logger::logDebug($json);
        $encoded = zlib_encode($json, ZLIB_ENCODING_GZIP, 9);
        $encrypted = AES::encryptIV($encoded, GWF_SALT);
        return $encrypted;
    }
    
    private static function cookieSecure()
    {
        return false; # TODO: Evaluate protocoll and OR with setting.
    }
    
    private static function setDummyCookie()
    {
        $app = Application::instance();
        if ( (!$app->isCLI()) && (!$app->isUnitTests()) )
        {
            setcookie(self::$COOKIE_NAME, self::DUMMY_COOKIE_CONTENT, Application::$TIME+300, '/', self::$COOKIE_DOMAIN, self::cookieSecure(), !self::$COOKIE_JS);
        }
    }
    
    private static function createSession()
    {
        $session = new self();
//         $session->cookieData['sess_id'] = (int)(Application::$MICROTIME * 1000000);
        $session->setCookie();
        return $session;
    }
    
}
