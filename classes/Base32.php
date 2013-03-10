<?php
namespace GoogleAuthenticator;

/**
 * This class in a minor modification of the publicly available implementation by Bryan Ruiz (bryan@bryanruiz.com)
 *
 * Original comments from Bryan below:
 *
 *     Encode in Base32 based on RFC 4648.
 *     Requires 20% more space than base64
 *     Great for case-insensitive filesystems like Windows and URL's (except for = char which can be excluded using the
 *     pad option for urls)
 *
 * @author  Yuriy Akopov
 * @date    2013-03-10
 */
class Base32 {
    protected static $_map = array(
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', //  7
        'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', // 15
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', // 23
        'Y', 'Z', '2', '3', '4', '5', '6', '7', // 31
        '='  // padding char
    );

    /**
     * Returns base32 alphabet (is used by GoogleClientAuthenticator to generate base32-correct random key)
     *
     * @param bool $includePadding
     *
     * @return array
     */
    public static function getAlphabet($includePadding = false) {
        $abc = self::$_map;

        // don't include padding character if not requested
        if (!$includePadding) {
            unset($abc[count($abc) - 1]);
        }

        return $abc;
    }

    /**
     * Encodes given string using base32 alphabet
     *
     * @author Bryan Ruiz
     *
     * @param   string  $input
     * @param   bool    $padding    use false when encoding for urls
     *
     * @return string
     */
    public static function encode($input, $padding = true) {
        if (strlen($input) === 0) {
            return '';
        }

        $input = str_split($input);
        $binaryString = '';

        for($i = 0; $i < count($input); $i++) {
            $binaryString .= str_pad(base_convert(ord($input[$i]), 10, 2), 8, '0', STR_PAD_LEFT);
        }

        $fiveBitBinaryArray = str_split($binaryString, 5);
        $base32 = '';
        $i=0;
        while($i < count($fiveBitBinaryArray)) {
            $base32 .= self::$map[base_convert(str_pad($fiveBitBinaryArray[$i], 5,'0'), 2, 10)];
            $i++;
        }

        if ($padding && ($x = strlen($binaryString) % 40) != 0) {
            if($x == 8) $base32 .= str_repeat(self::$_map[32], 6);
            else if($x == 16) $base32 .= str_repeat(self::$_map[32], 4);
            else if($x == 24) $base32 .= str_repeat(self::$_map[32], 3);
            else if($x == 32) $base32 .= self::$_map[32];
        }

        return $base32;
    }

    /**
     * Decodes given base32 string and returns original "binary" string
     * Returns false if it is invalid and cannot be decoded
     *
     * @param   string  $input
     *
     * @return  string|bool
     */
    public static function decode($input) {
        if(strlen($input) === 0) {
            return '';
        }

        $paddingCharCount = substr_count($input, self::$_map[32]);
        $allowedValues = array(6, 4, 3, 1, 0);
        if (!in_array($paddingCharCount, $allowedValues)) {
            return false;
        }

        for ($i = 0; $i < 4; $i++) {
            if(
                $paddingCharCount == $allowedValues[$i] &&
                substr($input, -($allowedValues[$i])) != str_repeat(self::$_map[32], $allowedValues[$i])
            ) {
                return false;
            }
        }

        $input = str_replace('=','', $input);
        $input = str_split($input);

        $binaryString = '';
        for ( $i=0; $i < count($input); $i = $i+8) {
            $x = '';
            if(!in_array($input[$i], self::$_map)) {
                return false;
            }

            $flippedMap = array_flip(self::$_map);
            for ($j = 0; $j < 8; $j++) {
                $x .= str_pad(base_convert(@$flippedMap[@$input[$i + $j]], 10, 2), 5, '0', STR_PAD_LEFT);
            }

            $eightBits = str_split($x, 8);
            for($z = 0; $z < count($eightBits); $z++) {
                $binaryString .= ( ($y = chr(base_convert($eightBits[$z], 2, 10))) || ord($y) == 48 ) ? $y:"";
            }
        }

        return $binaryString;
    }
}