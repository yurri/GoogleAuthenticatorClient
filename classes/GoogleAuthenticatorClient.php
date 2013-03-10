<?php
namespace GoogleAuthenticator;

require_once('Base32.php');

/**
 * General exception thrown by GoogleAuthenticatorClient
 *
 * @author  Yuriy Akopov
 * @date    2013-03-10
 */
class Exception extends \Exception {}

/**
 * An exception specifically identifying authentication errors
 *
 * @author  Yuriy Akopov
 * @date    2013-03-10
 */
class AuthException extends \GoogleAuthenticator\Exception {}

/**
 * Implements an interface to access Google Authenticator functionality
 *
 * Supports both counter-based and time-based authentication mechanisms
 *
 * Loosely based on other publicly available implementations:
 * 1) https://github.com/PHPGangsta/GoogleAuthenticator by Michael Kliewe
 * 2) http://dendory.net/twofactors by Patrick Lambert
 *
 * This class uses base32 encoding and decoding by Bryan Ruiz
 *
 * Usage:
 *
 * 1) When user is registered or enrolled into 2 factor authentication, generate a unique key for them with getNewKey()
 *    That key should be stored as it will be used every time user attempts to authenticate
 *
 * 2) Call getQrCodeUrl() to show them a QR code to set up their authenticator app
 *    If the QR code cannot be used or is not desired, ask user to enter the generated key into their app manually
 *    It is possible to set up two kind of accounts in the app - counter- and time-based
 *
 * 3) Once user's app is initialised, ask for that value when user needs to be authenticated and call
 *    verifyCode() supplying the value provided.
 *    The client must be set into a proper mode - counter or time-based (depending on what QR code user has been given)
 *
 *
 * @author  Yuriy Akopov
 * @date    2013-03-10
 */
class Client {
    // length of the code displayed by Google Authenticator app to user
    const CODE_LENGTH = 6;

    // Tolerance to time delays for supplied counter values (in seconds)
    // @todo: need to check if can be other than 30 sec
    const TOLERANCE_DELAY = 30;

    /**
     * Values allowed for code type parameter
     */
    const
        MODE_TOTP = 'totp',     // timer-based code
        MODE_HOTP = 'hotp'      // counter-based code
    ;

    /**
     * Authentication method to use, value is supposed to be one of self::CODE_TYPE_* constants
     *
     * @var string
     */
    protected $_codeType = null;

    /**
     * Unique key associated with the user used for encryption of communications
     *
     * @var string
     */
    protected $_key = null;

    /**
     * Mode the client is working in (counter- or time-based verification)
     *
     * @var string
     */
    protected $_mode = null;

    /**
     * Initialised authenticator client
     *
     * @param   string  $key        random alphanumeric key assigned to user, should be assigned on user registration
     *                              or enrollment into 2-factor authentication and be stored against the username
     * @param   string  $mode       counter or time base mode (self::MODE_*
     *
     * @throws  \GoogleAuthenticator\Exception
     */
    public function __construct($key, $mode = self::MODE_TOTP)
    {
        if (!self::validateKey($key)) {
            throw new \GoogleAuthenticator\Exception('Invalid key supplied (expected to contain base32 characters only)');
        }
        $this->_key = $key;

        if (!in_array($mode, array(self::MODE_HOTP, self::MODE_TOTP))) {
            throw new \GoogleAuthenticator\Exception('Invalid or unsupported mode supplied');
        }
        $this->_mode = $mode;
    }

    /**
     * Generates a new key basing on the allowed base32 alphabet
     *
     * @param   int   $length
     * @return  string
     */
    public static function getNewKey($length = 16) {
        $abc = \GoogleAuthenticator\Base32::getAlphabet();

        $key = '';
        for ($i = 0; $i < $length; $i++) {
            $key .= $abc[array_rand($abc)];
        }

        return $key;
    }

    /**
     * Checks if the code is correct
     * This will accept codes starting from $discrepancy*30sec ago to $discrepancy*30sec from now
     *
     * Returns matched attempt number within the allowed tolerance
     *
     * @param   string  $code       code user has provided from their app
     * @param   int     $seed       code generation seed (stored counter value for HOTP, timestamp for TOTP)
     * @param   int     $tolerance  allowed mismatch (ticks for HOTP, 30 sec units for TOTP)
     *
     * @return  int
     *
     * @throws  \GoogleAuthenticator\AuthException
     * @throws  \GoogleAuthenticator\Exception
     */
    public function verifyCode($code, $seed = null, $tolerance = 2)
    {
        if ((!is_null($seed)) and (!$this->_validateInt($seed, true))) {
            throw new \GoogleAuthenticator\Exception('Invalid seed value, must be positive int or 0, or null');
        }

        if (!$this->_validateInt($tolerance, true)) {
            throw new \GoogleAuthenticator\Exception('Invalid tolerance value, must be positive int or 0');
        }

        switch ($this->_mode) {
            case self::MODE_TOTP:
                $currentSeed = $this->_getTimeSlice($seed);
                // allowing some space for time mismatch
                $startFrom = (-1) * $tolerance;
                $startTo = $tolerance;
            break;

            case self::MODE_HOTP:
                $currentSeed = is_null($seed) ? 0 : $seed;
                // allowing some tolerance if the user has clicked "login" button several times or updated
                // counter in their map several times
                $startFrom  = max(0, ($currentSeed - $tolerance));
                $startTo    = $currentSeed + $tolerance;
            break;

            default:
                throw new \GoogleAuthenticator\Exception('Invalid mode, something went wrong');
        }

        // calculating code varying seed from from -tolerance to +tolerance
        // if any of them matches the one user provided, it's a success
        for ($i = $startFrom; $i <= $startTo; $i++) {
            switch ($this->_mode) {
                case self::MODE_TOTP:
                    $calculatedCode = $this->_getExpectedTotpCode($currentSeed + $i);
                break;

                case self::MODE_HOTP:
                    $calculatedCode = $this->_getExpectedHotpCode($i);
                break;

                default:
                    throw new \GoogleAuthenticator\Exception('Invalid mode, something went wrong');
            }

            if ($calculatedCode === $code) {
                return $i;
            }
        }

        throw new \GoogleAuthenticator\AuthException('Invalid code supplied or tolerance delay too short');
    }


    /**
     * Calculates a time-based code the user we specified on object creation is expected to see in their app
     *
     * @param   int $timeSlice
     *
     * @return  string
     */
    protected function _getExpectedTotpCode($timeSlice)
    {
        // Pack time into binary string
        $time = join('', array(chr(0), chr(0), chr(0), chr(0), pack('N*', $timeSlice)));

        // Hash it with users secret key
        $secret = \GoogleAuthenticator\Base32::decode($this->_key);
        $hm = hash_hmac('SHA1', $time, $secret, true);

        // Use last nipple of result as index/offset
        $offset = ord(substr($hm, -1)) & 0x0F;

        // grab 4 bytes of the result
        $hashpart = substr($hm, $offset, 4);

        // Unpak binary value
        $value = unpack('N', $hashpart);
        $value = $value[1];

        // Only 32 bits
        $value = $value & 0x7FFFFFFF;

        $modulo = pow(10, self::CODE_LENGTH);
        $code = str_pad($value % $modulo, self::CODE_LENGTH, '0', STR_PAD_LEFT);

        return $code;
    }

    /**
     * Calculates a counter-based code the user we specified on object creation is expected to see in their app
     *
     * @param   int $counter seed to build counter value from
     *
     * @return  string
     */
    protected function _getExpectedHotpCode($counter)
    {
        $key = pack("H*", $this->_getHexKey($this->_key));
        $length = 8;

        // initialising the counter value from the seed given
        $curCounter = array_fill(0, $length, 0);
        for($i = ($length - 1); $i >= 0; $i--)
        {
            $curCounter[$i] = pack ('C*', $counter);
            $counter = $counter >> $length;
        }

        // 'binarising' counter
        $binCounter = implode($curCounter);
        if(strlen($binCounter) < $length) {
            $binCounter = str_repeat(chr(0), 8 - strlen ($binCounter)) . $binCounter;
        }

        // encrypting the counter value in a hash using the secret key
        $hash = hash_hmac ('SHA1', $binCounter, $key);

        // truncating into code expected from user
        foreach(str_split($hash, 2) as $hex) {
            $hmac_result[] = hexdec($hex);
        }
        $offset = $hmac_result[19] & 0xf;

        $code =(
            (($hmac_result[$offset+0] & 0x7f) << 24 ) |
            (($hmac_result[$offset+1] & 0xff) << 16 ) |
            (($hmac_result[$offset+2] & 0xff) << 8 ) |
            ($hmac_result[$offset+3] & 0xff)
        ) % pow(10, self::CODE_LENGTH);

        return (string) $code;
    }

    /**
     * Returns URL to QRCode for Google Authenticator authorisation with camera
     * Typical usage - show that to user in an iframe
     *
     * @param   string  $username   name to appear in app config created from QR code generated
     * @param   int     $width      desired QR code image height (width) size in pixels
     * @param   int     $height     if null or omitted is considered equal to $width
     *
     * @return  string
     *
     * @throws  \GoogleAuthenticator\Exception
     */
    public function getQrCodeUrl($username, $width = 150, $height = null) {
        $urlParams = array(
            'cht'   => 'qr',
            'chl'   => $this->_getOtpUri($username)
        );

        if (self::_validateInt($width)) {
            if (is_null($height)) {
                $height = $width;
            } else if (!self::_validateInt($height)) {
                throw new \GoogleAuthenticator\Exception('Invalid QR code height supplied');
            }

            $urlParams['chs'] = (string) $width . 'x' . (string) $height;
        } else {
            throw new \GoogleAuthenticator\Exception('Invalid QR code width supplied');
        }

        $url = 'https://chart.googleapis.com/chart?' . http_build_query($urlParams);

        return $url;
    }

    /**
     * Returns URI to authenticator code generator
     * Is not supposed to be used directly but supplied as a parameter to Google
     * Basically this URL is a structure to hold more parameters as one
     *
     * Format description: http://code.google.com/p/google-authenticator/wiki/KeyUriFormat
     *
     * @param   string  $username
     * @return  string
     */
    protected function _getOtpUri($username) {
        $otpAuthParams = array(
            'secret'    => $this->_key,
            'counter'   => '0'
        );
        $uri =
            'otpauth://' .
            $this->_codeType .
            '/' .
            $this->_sanitiseUserName($username) .
            '/' .
            urlencode('?' . http_build_query($otpAuthParams))
        ;

        return $uri;
    }

    /**
     * Helper function checking if the supplied value is a positive integer
     *
     * @static
     *
     * @param   mixed   $value
     * @param   bool    $allowZero
     *
     * @return  bool
     */
    protected static function _validateInt($value, $allowZero = false)
    {
        if (!preg_match('/^[1-9][0-9]*$/', $value)) {
            if ($allowZero) {
                if (((string) $value) !== '0') {
                    return false;
                }
            } else {
                return false;
            }
        }

        return true;
    }

    /**
     * Checks if the supplied only contains allowed base32 characters as it is expected to
     *
     * @static
     *
     * @param   string  $key
     *
     * @return  bool
     */
    public static function validateKey($key) {
        $chars = str_split($key);
        $abc = \GoogleAuthenticator\Base32::getAlphabet();

        foreach ($chars as $ch) {
            if (!in_array($ch, $abc)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Returns time for counter where one 'tick' is defined by tolerance
     *
     * @param   int|null    $timestamp
     *
     * @return  int
     */
    protected function  _getTimeSlice($timestamp = null) {
        if (is_null($timestamp)) {
            $timestamp = time();
        }

        return (int) floor($timestamp / self::TOLERANCE_DELAY);
    }

    /**
     * Helper function converting base32 key into a hex value required by counter mechanism
     *
     * @return string
     */
    protected function _getHexKey() {
        $alphabet = join('', \GoogleAuthenticator\Base32::getAlphabet());
        $out    = '';
        $dous   = '';

        for($i = 0; $i < strlen($this->_key); $i++)
        {
            $in = strrpos($alphabet, $this->_key[$i]);
            $b  = str_pad(base_convert($in, 10, 2), 5, '0', STR_PAD_LEFT);
            $out    .= $b;
            $dous   .= $b .'.';
        }
        $ar = str_split($out,20);
        $out2 = '';
        foreach($ar as $val)
        {
            $rv = str_pad(base_convert($val, 2, 16), 5, '0', STR_PAD_LEFT);
            $out2 .= $rv;
        }

        return $out2;
    }

    /**
     * Helper function to make supplied username clean and URL-safe
     *
     * @param $username
     *
     * @return string
     *
     * @throws \GoogleAuthenticator\Exception
     */
    protected function _sanitiseUserName($username) {
        $username = preg_replace('/[^a-zA-Z0-9@\.]+/', '', $username);

        if (strlen($username) === 0) {
            throw new \GoogleAuthenticator\Exception('Username does not contain any safe characters');
        }

        return $username;
    }
}