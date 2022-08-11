<?php

namespace Tests;

use Fize\Security\SpecialRSA;
use PHPUnit\Framework\TestCase;

class TestSpecialRSA extends TestCase
{

    public function testToPKCS8PrivateKeyFile1()
    {
        $privateKey = "MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAKOoelzwAU5Asw9zknkTYGvfZr0Ap6ZDL6NMSNRYZ2maVJd5xOfSRqTkEq1Ne*h2Qe3wCKdxo0SuCVWNjM-nd3af*fb4YcWdlDuHaA1s28I5hZtVp2sbF*nvgdeUwSz-X0hQGcaqVzcTKDH9l2XuMC**OEofyyosU2jvEIGdwqSNAgMBAAECgYAkojvxvc*tApKSbN5mt82nl-RZbmIYt4VcWmEbF0bevqsc1SccdVdW5a7AmE2aNY6AgnCNesR-RS3Vtr-Ech2tVfwMXypJsXN5hq0uyM6iDkE6kFhGL1zui72u9RQJvdB7CsNfEONIaFlX46MUOdF0fR2n-sGLMc1qzpj*L3k6QQJBAOJfQRF6ehE5d1Sm*7q9uObte1ubako89TSGZmCOk-3vpm9CRTey-18Ids98yMNg3Wy53M4oEzjwjdnnulX9PpUCQQC5E-NySYbigVCsO5Tjr*iAA1ykdGIgaRM45s2tvbMLYQdZYhnkPRjSj*Y7I915cp5klQ75T260InPYQqBkb2gZAkEAjRYtKcWZ*s5EL4B7eCHy8gqlTa0JjAd*FCSH-joexq-snX9CQLrRKtvNoPf28L6YgsE8e0jC4kQbROqGWj2iGQJBAKkXVUCBdL7UrsPs26b6PE1YxPdrbYt29Jz0Ic4ulro6t*AuBMHGIDugRRSbO*mNkrEKjlew-s*M*pIGrUuVjWECQQC3qMemXCmqp7lAaSqYy9Rk8HNVgEeDqJfhcIS4SrRH0DSExPE9yfhadaiC4IIYmmK5L*2V3dxIUI7KXbeO*ptz";
        $saveFile = '/assets/certs/EFQ/sign_private_pkcs8.pem';
        SpecialRSA::toPKCS8PrivateKeyFile($privateKey, $saveFile);
        self::assertTrue(true);
    }

    public function testToPKCS8PrivateKeyFile2()
    {
        $privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIVmdRXPTvC5B8jmR-e45polymr5bfJCEmchfaT8QrAplpKTK5e62TRNerBP8ZfEhAmqaSMu6n4c3sfW4Xskx-GXTQCedwcHzYupRApDB-nBx0NM2G8otC2NGgsTevLoBGhge7kCRk8pbuwwzij5R6A*VKvjmnhmwrSJV2OqaBl-AgMBAAECgYEAglrpZSOMJy0YD1f-0XFsXgs5rqkIqCeqZf7TEWq0HAK3sYmAmqcqYrKnhizIjx6oS*2rCYdp*0xo4mz3L2d0vRVEdHB34IE3OkHs96XiSyizsknTJgQR7SrmsnHWN9cLaGOYNysn9YN3cxyhQXqlpOnE*rSge10HNJiHCtrYTBECQQDAKBho-qcP8WSN*JcvsmmW7ScTO5JJZ-GOHTjEcNC-tIDLLvIsN41mSCKhmDhb9IE6-bLyIT2fSHufw55J6pdZAkEAsbjUWIzr-HM54MNpDfY-f8Qj7xxYgx34loHOk7aDJXLvut*YeO3FdlU3HOgNqQtw2djEc1FPq-oNzhqx7gj0lwJAU2qUfi-eEju2bTM3XotS7yPwTJcVwCwRXqIs3Iok9LPFHW85zhwnk-lIn2HXRYP0-cjYf*gSOi1bDVX8RxZBsQJBAJnvKtYMMbb3IxGgkFUMjpGfFTTdy3i*M-xBMOnWsx9zv1uQoiNUZ62IP-VktbhO9Y9rZzUvH6ApNV3o12cDEL8CQAMTQ1V6q3HVRP6tZobCxeozEdX7uwxjWFrZr9xV6V6xAdLRLvgfH4I9dW3Y2CKw9V8zPnMPH*rlNWOnVyVnYFg=";
        $saveFile = '/assets/certs/EFQ/data_private_pkcs8.pem';
        SpecialRSA::toPKCS8PrivateKeyFile($privateKey, $saveFile);
        self::assertTrue(true);
    }

    public function testToPKCS1PrivateKeyFile1()
    {
        $pkcs8File = '\assets\certs\EFQ\sign_private_pkcs8.pem';
        $pkcs1File = '\assets\certs\EFQ\sign_private_pkcs1.pem';
        $output = SpecialRSA::toPKCS1PrivateKeyFile($pkcs8File, $pkcs1File);
        var_dump($output);
        self::assertEmpty($output);
    }

    public function testToPKCS1PrivateKeyFile2()
    {
        $pkcs8File = '\assets\certs\EFQ\data_private_pkcs8.pem';
        $pkcs1File = '\assets\certs\EFQ\data_private_pkcs1.pem';
        $output = SpecialRSA::toPKCS1PrivateKeyFile($pkcs8File, $pkcs1File);
        var_dump($output);
        self::assertEmpty($output);
    }

    public function testToPublicKeyFile1()
    {
        $publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCFZnUVz07wuQfI5kf3uOaaJcpq*W3yQhJnIX2k-EKwKZaSkyuXutk0TXqwT-GXxIQJqmkjLup*HN7H1uF7JMfxl00AnncHB82LqUQKQwf5wcdDTNhvKLQtjRoLE3ry6ARoYHu5AkZPKW7sMM4o*UegPlSr45p4ZsK0iVdjqmgZfwIDAQAB";
        $saveFile = '/assets/certs/EFQ/data_public.pem';
        SpecialRSA::toPublicKeyFile($publicKey, $saveFile);
        self::assertTrue(true);
    }

    public function testToPublicKeyFile2()
    {
        $publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCjqHpc8AFOQLMPc5J5E2Br32a9AKemQy*jTEjUWGdpmlSXecTn0kak5BKtTXvodkHt8AincaNErglVjYzP53d2n-n2*GHFnZQ7h2gNbNvCOYWbVadrGxfp74HXlMEs-19IUBnGqlc3Eygx-Zdl7jAvvjhKH8sqLFNo7xCBncKkjQIDAQAB";
        $saveFile = '/assets/certs/EFQ/sign_public.pem';
        SpecialRSA::toPublicKeyFile($publicKey, $saveFile);
        self::assertTrue(true);
    }

    public function testPublicEncrypt1()
    {
        $publicKeyFile = '/assets/certs/EFQ/data_public.pem';
        $data = 'MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIVmdRXPTvC5B8jmR-e45polymr5bfJCEmchfaT8QrAplpKTK5e62TRNerBP8ZfEhAmqaSMu6n4c3sfW4Xskx-GXTQCedwcHzYupRApDB-nBx0NM2G8otC2NGgsTevLoBGhge7kCRk8pbuwwzij5R6A*VKvjmnhmwrSJV2OqaBl-AgMBAAECgYEAglrpZSOMJy0YD1f-0XFsXgs5rqkIqCeqZf7TEWq0HAK3sYmAmqcqYrKnhizIjx6oS*2rCYdp*0xo4mz3L2d0vRVEdHB34IE3OkHs96XiSyizsknTJgQR7SrmsnHWN9cLaGOYNysn9YN3cxyhQXqlpOnE*rSge10HNJiHCtrYTBECQQDAKBho-qcP8WSN*JcvsmmW7ScTO5JJZ-GOHTjEcNC-tIDLLvIsN41mSCKhmDhb9IE6-bLyIT2fSHufw55J6pdZAkEAsbjUWIzr-HM54MNpDfY-f8Qj7xxYgx34loHOk7aDJXLvut*YeO3FdlU3HOgNqQtw2djEc1FPq-oNzhqx7gj0lwJAU2qUfi-eEju2bTM3XotS7yPwTJcVwCwRXqIs3Iok9LPFHW85zhwnk-lIn2HXRYP0-cjYf*gSOi1bDVX8RxZBsQJBAJnvKtYMMbb3IxGgkFUMjpGfFTTdy3i*M-xBMOnWsx9zv1uQoiNUZ62IP-VktbhO9Y9rZzUvH6ApNV3o12cDEL8CQAMTQ1V6q3HVRP6tZobCxeozEdX7uwxjWFrZr9xV6V6xAdLRLvgfH4I9dW3Y2CKw9V8zPnMPH*rlNWOnVyVnYFg=';
        $encrypted = SpecialRSA::publicEncrypt($data, $publicKeyFile);
        print $encrypted;
        // T14lbLJ93T7NKIbT2YcSMtwQsVnlCNKRGOTxX5PNY+SPezv5L0IMR1WnkaHC4WTJ05A8leOtkJVyijYQPCxosgtAOiqZCANr6IhaqGLtbIfjh0dKbDLqtaCQsFZ5NWRmUzKRcURQVEYNIJciq0mqgSUMSDMj0cY3bfpnbLsPwf4=
        self::assertNotEmpty($encrypted);
    }

    public function testPublicEncrypt2()
    {
        $publicKeyFile = '/assets/certs/EFQ/sign_public.pem';
        $data = '123456';
        $encrypted = SpecialRSA::publicEncrypt($data, $publicKeyFile);
        print $encrypted;
        // KoYrdwpnMBBH62Kvyr0PiMEChpAEzyBw4UL3CZ3Cn9atyc4AgvuDMd75SAEdp0VyFIvSB9ohAqG1yG6pHx2AdJhhrFVf9M6XdNgs0QkVQC0r0SUV/xqi4FImz3UiXlhtGxaxqdivuOEoMDdUsdSagMKI7Y8zB53Mp2irvnsLfcg=
        self::assertNotEmpty($encrypted);
    }

    public function testPrivateDecrypt1()
    {
        $privateKeyFile = '\assets\certs\EFQ\data_private_pkcs1.pem';
        $encrypted = 'eFAbGh3QxWViWloMmln7m5bv6HksNniHU6HAiUbbGxqs+8cPGm3Biud1D6HR8yi7WY/uS4xs21q9MOfwDXEghp5u6E11Zc6MSV5XoPYkStwDsVhkOfx/aDCtV3v+wdjQu6jC1KxwsrEx77+nPW9fWNK8qomitZFw6E2/k92+Y7aBW5+MlKQbtgIcZXKqLV5X7TjeMDAuMwGA0L1vS/oePj476XNUWTz8TT1sqhfZ1G1nqinQJeimXc5Ogo861r5F6QJ9uAurOYtQkNp2mYD0IDDDGRT2FBsTmRuF2oZNJXwF2jCRMAwsw1A+Vup2TWnK2P5XoWm3d6WnuqtPvjRKQGjaZo6goPqLedHL9XWasdg2BJvRITUfqPvm7uLLWn7IfnC4ZatisVtmlA/kzCm7ftbLwDbSmofarXt5TlrnifFddomXCDi54kjh9ZABl6I6QFvyI3RDKSen3OmJS8a+vWdFNPCuZAUK83vZ40v64FdfV/E3jO00VEJnTm09ZunWcquL/Y6JzBkNO8AohiLDALkVvd+PNabZEhYTFt4+g8tV49aw2X+fv+w9bpR8jCiskOZJutxPLT8qkgwM5fdOGUUsGQU1pnMsLjrqgmhxsvNHMGaxtoYIP0n6JoBxlpPUgD95OcRJeOladp/MD/07lumBFeVk/T5tVGOssh6YAy9uUSkQHsPQwOQxUaaVTcwU07ypoEZw2R+KktqmvF0QmxNZjgts/ep0pMZLSzl7I2XmYQGAx8xXBsKBlqRJ3AAQ6ed7XKXj0vE5ebfLedp9c4eRJD4Ne7FzDwVc6PVCtG41IjELhVGitE1AU/2rUZjkzxEQ97UAf6T3j1euBzve4k69gfwoo9RJI3u9rsmQvbwCOFplhlmwqTi3IUZanMLWz/aFPDPvneGP4AGUslcUXe6er2eLiadm8O/48wwFxiFkxCrfQ0pxK0NQwSQAsigCfE7YLUswRnnEEGf/1vZBIWmzyCjCIWS1Ma7ZuhY0HAPoAnIX7ru21MxH5KJakOx5dAi2lV0dT9hmtu+M4QfJTOZpIGOVWNCRzJ2eyLLSF48dF0gqjr1C1CEGDvwbAs7Xaehp4UolWb/3/Lil13/o4VUnUQugZlxdEKRIJsuRkqbqZn637EDM8xW9oaCMaxY17yEjXx0Kt2x4s3WRrJNfLFLP2aISCRm9r8fJoyZJjQUzn8t+wU1X3XCbTusXxjPoeoWmxckWA+u5lwAKTatVyuN1alIa+ooKK+ffLgOy+bS2WjLoHp+H2gX/HbaXzW00pgv+ZKeb5JE/3glcU4L+413Kxw7nPyKOugFYehtumUjIdBlbe6LE46C2mujPtxm0abPJBAR3jqIg4XYURqIDdg==';
        $data = SpecialRSA::privateDecrypt($encrypted, $privateKeyFile);
        print $data;
        $data2 = 'MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAIVmdRXPTvC5B8jmR-e45polymr5bfJCEmchfaT8QrAplpKTK5e62TRNerBP8ZfEhAmqaSMu6n4c3sfW4Xskx-GXTQCedwcHzYupRApDB-nBx0NM2G8otC2NGgsTevLoBGhge7kCRk8pbuwwzij5R6A*VKvjmnhmwrSJV2OqaBl-AgMBAAECgYEAglrpZSOMJy0YD1f-0XFsXgs5rqkIqCeqZf7TEWq0HAK3sYmAmqcqYrKnhizIjx6oS*2rCYdp*0xo4mz3L2d0vRVEdHB34IE3OkHs96XiSyizsknTJgQR7SrmsnHWN9cLaGOYNysn9YN3cxyhQXqlpOnE*rSge10HNJiHCtrYTBECQQDAKBho-qcP8WSN*JcvsmmW7ScTO5JJZ-GOHTjEcNC-tIDLLvIsN41mSCKhmDhb9IE6-bLyIT2fSHufw55J6pdZAkEAsbjUWIzr-HM54MNpDfY-f8Qj7xxYgx34loHOk7aDJXLvut*YeO3FdlU3HOgNqQtw2djEc1FPq-oNzhqx7gj0lwJAU2qUfi-eEju2bTM3XotS7yPwTJcVwCwRXqIs3Iok9LPFHW85zhwnk-lIn2HXRYP0-cjYf*gSOi1bDVX8RxZBsQJBAJnvKtYMMbb3IxGgkFUMjpGfFTTdy3i*M-xBMOnWsx9zv1uQoiNUZ62IP-VktbhO9Y9rZzUvH6ApNV3o12cDEL8CQAMTQ1V6q3HVRP6tZobCxeozEdX7uwxjWFrZr9xV6V6xAdLRLvgfH4I9dW3Y2CKw9V8zPnMPH*rlNWOnVyVnYFg=';
        self::assertEquals($data2, $data);
    }

    public function testPrivateDecrypt2()
    {
        $privateKeyFile = '\assets\certs\EFQ\sign_private_pkcs1.pem';
        $encrypted = 'KoYrdwpnMBBH62Kvyr0PiMEChpAEzyBw4UL3CZ3Cn9atyc4AgvuDMd75SAEdp0VyFIvSB9ohAqG1yG6pHx2AdJhhrFVf9M6XdNgs0QkVQC0r0SUV/xqi4FImz3UiXlhtGxaxqdivuOEoMDdUsdSagMKI7Y8zB53Mp2irvnsLfcg=';
        $data = SpecialRSA::privateDecrypt($encrypted, $privateKeyFile);
        print $data;
        $data2 = '123456';
        self::assertEquals($data2, $data);
    }

    public function testPrivateSign1()
    {
        $privateKeyFile = '\assets\certs\EFQ\data_private_pkcs1.pem';
        $data = '123456';
        $sign = SpecialRSA::privateSign($data, $privateKeyFile);
        print $sign;
        self::assertNotEmpty($sign);
    }

    public function testPrivateSign2()
    {
        $privateKeyFile = '\assets\certs\EFQ\sign_private_pkcs1.pem';
        $data = '123456';
        $sign = SpecialRSA::privateSign($data, $privateKeyFile);
        print $sign;
        self::assertNotEmpty($sign);
    }

    public function testPublicVerify()
    {
        $publicKeyFile = '/assets/certs/EFQ/data_public.pem';
        $data = '123456';
        $sign = 'gmBz8zhyv8FZcdWVAPs8kXsr81jjhmB1emwNVB5c37m-Ymf4Oq6oL5lCqwC6aj3vZYSBZ4QVYIZ6uwdiE9nLI*E0ql-X-lTSxwJURnAhllX8PefVvDyyrE4sw5H*I6axl29fUCfBiYtf6WO7GFbOZyTdMdh6az0lDomyieVo9xA=';
        $result = SpecialRSA::publicVerify($data, $sign, $publicKeyFile);
        print $result;
        self::assertEquals(1, $result);
    }

    public function testPublicVerify2()
    {
        $publicKeyFile = '/assets/certs/EFQ/sign_public.pem';
        $data = '123456';
        $sign = 'MyZBfTvCBWruo6ZRDnbzEbZOYC76eXOZhpF0wuVjGpFVTS8vQk77tNooPDcDGG9C8iHfoPFscoUfAY9ix9Q6y42eazZMjnodcxK8hDMKn-dEGYKa70DESmHijRJuB0FBm4wSY62jp04SdXdnR9sRzh0fi1Cas-cNQgHgkYPXu1E=';
        $result = SpecialRSA::publicVerify($data, $sign, $publicKeyFile);
        print $result;
        self::assertEquals(1, $result);
    }
}
