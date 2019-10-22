package com.cj.utils;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

/**
 * aes 加密解密
 */
public class AESUtil {

    private static ThreadLocal<Cipher> cipherThreadLocal = new ThreadLocal<>();
    private static ThreadLocal<IvParameterSpec> iVThreadLocal = new ThreadLocal<>();

    /**
     * 加密
     *
     * @param content
     * @param strKey
     * @return
     * @throws Exception
     */
    public static byte[] encrypt(String content, String strKey) throws Exception {
        SecretKeySpec skeySpec = getKey(strKey);
        getCipher().init(Cipher.ENCRYPT_MODE, skeySpec, getIvParameterSpec());
        return getCipher().doFinal(content.getBytes());
    }

    /**
     * 解密
     *
     * @param strKey
     * @param content
     * @return
     * @throws Exception
     */
    public static String decrypt(byte[] content, String strKey) throws Exception {
        SecretKeySpec skeySpec = getKey(strKey);
//        修改为 threadLocal 从而 提高性能
//        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//        IvParameterSpec iv = new IvParameterSpec("0102030405060708".getBytes());
        getCipher().init(Cipher.DECRYPT_MODE, skeySpec, getIvParameterSpec());
        byte[] original = getCipher().doFinal(content);
        return new String(original);
    }

    private static SecretKeySpec getKey(String strKey) throws Exception {
        byte[] arrBTmp = strKey.getBytes();
        byte[] arrB = new byte[16]; // 创建一个空的16位字节数组（默认值为0）

        for (int i = 0; i < arrBTmp.length && i < arrB.length; i++) {
            arrB[i] = arrBTmp[i];
        }

        return new SecretKeySpec(arrB, "AES");
    }


    /**
     * base 64 encode
     *
     * @param bytes 待编码的byte[]
     * @return 编码后的base 64 code
     */
    public static String base64Encode(byte[] bytes) {
        return new String(Base64.getEncoder().encode(bytes));
    }

    /**
     * base 64 decode
     *
     * @param base64Code 待解码的base 64 code
     * @return 解码后的byte[]
     * @throws Exception
     */
    public static byte[] base64Decode(String base64Code) throws Exception {
        return base64Code.isEmpty() ? null : Base64.getDecoder().decode(base64Code.getBytes());
    }

    /**
     * AES加密为base 64 code
     *
     * @param content    待加密的内容
     * @param encryptKey 加密密钥
     * @return 加密后的base 64 code
     * @throws Exception //加密传String类型，返回String类型
     */
    public static String aesEncrypt(String content, String encryptKey) throws Exception {
        return base64Encode(encrypt(content, encryptKey));
    }

    /**
     * 将base 64 code AES解密
     *
     * @param encryptStr 待解密的base 64 code
     * @param decryptKey 解密密钥
     * @return 解密后的string   //解密传String类型，返回String类型 
     * @throws Exception
     */
    public static String aesDecrypt(String encryptStr, String decryptKey) throws Exception {
        return encryptStr.isEmpty() ? null : decrypt(base64Decode(encryptStr), decryptKey);
    }


    public static void main(String[] args) throws Exception {
        String key = "ase_key_rsj";
        for(int i = 0; i< 100 ; i++){
            long start = System.currentTimeMillis();
            String encrypt = aesEncrypt("沙发上" + i, key);
            System.out.println(encrypt + ":::" + (System.currentTimeMillis() - start) );
            start = System.currentTimeMillis();
            String decrypt = aesDecrypt(encrypt, key);
            System.out.println(decrypt + "::::" + (System.currentTimeMillis() - start) );
        }
    }

    private static Cipher getCipher(){
        if(null == cipherThreadLocal.get()){
            try {
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                cipherThreadLocal.set(cipher);
                return cipher;
            } catch (Exception  e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }
        return cipherThreadLocal.get();
    }

    private static IvParameterSpec getIvParameterSpec(){
        if(null == iVThreadLocal.get()){
            try {
                IvParameterSpec iv = new IvParameterSpec("0102030405060708".getBytes());
                iVThreadLocal.set(iv);
                return iv;
            } catch (Exception  e) {
                e.printStackTrace();
                throw new RuntimeException(e);
            }
        }
        return iVThreadLocal.get();
    }

}