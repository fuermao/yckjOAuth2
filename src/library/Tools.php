<?php


namespace OAuth2\library;


class Tools
{
    /**
     * 随机生成字符串
     * @param int $length 随机生成字符串长度
     * @param bool $isContainsLetter 是否包含字母，true 包含，false 不包含；默认为：true
     * @param bool $isContainsUpper 是否包含大写字母，true 包含，false 不包含；默认为：false
     * @param bool $isContainsSymbols 是否包含符号，true 包含，false 不包含；默认为：false
     * @return string
     */
    public static function randomString(int $length,bool $isContainsLetter = true,bool $isContainsUpper=false,bool $isContainsSymbols=false): string {
        $numbers        = "123456789";
        $lettersLower   = "qwertyuipasdfghjkzxcvbnm";
        $lettersUpper   = "QWERTYUPASDFGHJKZXCVBNM";
        $symbols   = "!@#$%^&*_";

        $str = "";
        // 判断需要组装的那些
        $letterArr = [];
        array_push($letterArr,$numbers);
        // 是否包含字母
        if($isContainsLetter){
            array_push($letterArr,$lettersLower);
        }
        // 是否包含大写字母
        if($isContainsUpper){
            array_push($letterArr,$lettersUpper);
        }
        // 是否包含符号
        if($isContainsSymbols){
            array_push($letterArr,$symbols);
        }

        // 所有标识符字符长度
        $totalLen = mb_strlen(implode("",$letterArr));
        // 尽量保证字符串不重复
        if($length <= $totalLen && count($letterArr) == 1){
            $str = mb_substr(str_shuffle(implode("",$letterArr)),0,$length);
        }else{
            while (mb_strlen($str) < $length){
                // 随机选取字符串
                $arrIndex = rand(0,count($letterArr)-1);
                $strIndex = rand(0,mb_strlen($letterArr[$arrIndex])-1);
                $randomLetter = $letterArr[$arrIndex][$strIndex];
                // 查找生成字符是否已经出现过
                $result = strstr($str,$randomLetter)? true:false;
                if($result){
                    // 目标长度大于或等于字符串总长度时，则允许重复
                    if($length >= $totalLen){
                        $str.=$randomLetter;
                    }
                }else{
                    $str.=$randomLetter;
                }
            }
        }
        return $str;
    }

}