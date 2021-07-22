package com.hmac.aws;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.TimeZone;

public class HMacGenerator {
    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();
    public static void main(String[] args) {
        // String kSecret = "oY+s/20opAh7DLeC5fVkHxQ+RNzG16GjZw/iWAp2";
        String accessKey = "";
        String secretKey = "AKIDEXAMPLE";
        String service = "iam";
        String host = "iam.amazonaws.com";
        String region = "us-east-1";

        String method = "GET";
        String url = "iam.amazonaws.com";
        String reqPath = "/";
        String reqQueryString = "Action=ListUsers&Version=2010-05-08";
        String request_parameters = "";
        String body = "";
        // SimpleDateFormat amzDate = new SimpleDateFormat( "yyyyMMdd'T'HHmmss'Z'" );
        String signedHeaders = "content-type;host;x-amz-date";

        String algorithm = "AWS4-HMAC-SHA256";

        Date now = new Date();
        SimpleDateFormat amzFormat = new SimpleDateFormat( "yyyyMMdd'T'HHmmss'Z'" );
        SimpleDateFormat stampFormat = new SimpleDateFormat( "yyyyMMdd" );
        amzFormat.setTimeZone(TimeZone.getTimeZone("UTC"));  //server timezone
        stampFormat.setTimeZone(TimeZone.getTimeZone("UTC"));

        String amzDate = amzFormat.format(now);
        String dateStamp = stampFormat.format(now);

        try {
            // String canonicalRequest = generateCanonicalRequest(method, reqPath, reqQueryString, url, body, amzDate);
            String canonicalRequest = generateCanonicalRequest(method, reqPath, reqQueryString, url, body, amzDate, signedHeaders);
            System.out.println("Canonical request:\n" + canonicalRequest);

            String canonicalRequestHash = generateCanonicalRequestHash(canonicalRequest);
            System.out.println("\n\nCanonical request hash:\n" + canonicalRequestHash);

            String stringToSign = generateStringToSign(algorithm, amzDate, dateStamp, region, service, canonicalRequestHash);
            System.out.println("\n\nString to sign:\n" + stringToSign);

            byte[] kSign = getSignatureKey(secretKey, dateStamp, region, service);
            String signature = bytesToHex(HmacSHA256(stringToSign, kSign)).toLowerCase(Locale.ROOT);
            System.out.println("\n\nSignature:\n" + signature);

            String authorizationHeader = String.format("Authorization: %s Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%s", algorithm, secretKey, dateStamp, region, service, signedHeaders, signature);
            System.out.println("\n\nAuthorization header:\n" + authorizationHeader);

        } catch(Exception ex) {
            System.out.println(ex);
        }
    }

    static String generateStringToSign(String algorithm, String amzDate, String dateStamp, String region, String service, String canonicalRequestHash) {
        return String.format("%s\n%s\n%s/%s/%s/aws4_request\n%s", algorithm, amzDate, dateStamp, region, service, canonicalRequestHash);
    }

    static String generateCanonicalRequest(String method, String reqPath, String reqQueryString, String url, String body, String date, String signedHeaders) throws Exception {
        // Arrumar headers: Talvez dê problema por conta da geração do hash
        // String canonicalHeaders = "content-type:application/x-www-form-urlencoded; charset=utf-8\n" + "host:" + url + "\n" + "x-amz-date:" + date + "\n";
        String canonicalHeaders = "host:" + url + "\n" + "x-amz-date:" + date + "\n";


        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(body.getBytes(StandardCharsets.UTF_8));
        String hashHex = bytesToHex(hash).toLowerCase(Locale.ROOT);

        return method + '\n' +
                    reqPath + '\n' +
                    reqQueryString + '\n' +
                    canonicalHeaders + '\n' +
                    signedHeaders + '\n' +
                    hashHex;
    }

    static String generateCanonicalRequestHash(String canonicalRequest) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(canonicalRequest.getBytes(StandardCharsets.UTF_8));
        return bytesToHex(hash).toLowerCase(Locale.ROOT);
    }

    static byte[] HmacSHA256(String data, byte[] key) throws Exception {
        String algorithm="HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);
        mac.init(new SecretKeySpec(key, algorithm));
        return mac.doFinal(data.getBytes("UTF-8"));
    }

    static byte[] getSignatureKey(String key, String dateStamp, String regionName, String serviceName) throws Exception {
        byte[] kSecret = ("AWS4" + key).getBytes("UTF-8");
        byte[] kDate = HmacSHA256(dateStamp, kSecret);
        byte[] kRegion = HmacSHA256(regionName, kDate);
        byte[] kService = HmacSHA256(serviceName, kRegion);
        byte[] kSigning = HmacSHA256("aws4_request", kService);
        return kSigning;
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }
}
