/*
 * Copyright 2012-2017 Brian Campbell
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.jose4j.jwx;

import org.jose4j.base64url.Base64;
import org.jose4j.json.JsonUtil;
import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jws.AlgorithmIdentifiers;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.lang.IntegrityException;
import org.jose4j.lang.JoseException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

/**
 */
public class JsonWebStructureTest
{
    private static final String YOU_LL_GET_NOTHING_AND_LIKE_IT = "You'll get nothing, and like it!";

    private JsonWebKey oct256bitJwk;

    @Before
    public void symmetricJwk() throws JoseException
    {
        String json = "{\"kty\":\"oct\",\"kid\":\"9er\",\"k\":\"Ul3CckPpDfGjBzSsXCoQSvX3L0qVcAku2hW9WU-ccSs\"}";
        oct256bitJwk = JsonWebKey.Factory.newJwk(json);
    }

    @Test
    public void jws1() throws JoseException
    {
        String cs = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjllciJ9." +
                "WW91J2xsIGdldCBub3RoaW5nLCBhbmQgbGlrZSBpdCE." +
                "45s_xV_ol7JBwVcTPbWbaYT5i4mb7j27lEhi_bxpExw";
        JsonWebStructure jwx = JsonWebStructure.fromCompactSerialization(cs);
        Assert.assertTrue(cs + " should give a JWS " + jwx, jwx instanceof JsonWebSignature);
        Assert.assertEquals(AlgorithmIdentifiers.HMAC_SHA256, jwx.getAlgorithmHeaderValue());
        jwx.setKey(oct256bitJwk.getKey());
        String payload = jwx.getPayload();
        Assert.assertEquals(YOU_LL_GET_NOTHING_AND_LIKE_IT, payload);
        Assert.assertEquals(oct256bitJwk.getKeyId(), jwx.getKeyIdHeaderValue());
    }

    @Test (expected = IntegrityException.class)
    public void integrityCheckFailsJws() throws JoseException
    {
        String cs = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjllciJ9." +
                "RGFubnksIEknbSBoYXZpbmcgYSBwYXJ0eSB0aGlzIHdlZWtlbmQuLi4gSG93IHdvdWxkIHlvdSBsaWtlIHRvIGNvbWUgb3ZlciBhbmQgbW93IG15IGxhd24_." +
                "45s_xV_ol7JBwVcTPbWbaYT5i4mb7j27lEhi_bxpExw";
        JsonWebStructure jwx = JsonWebStructure.fromCompactSerialization(cs);
        Assert.assertTrue(cs + " should give a JWS " + jwx, jwx instanceof JsonWebSignature);
        Assert.assertEquals(AlgorithmIdentifiers.HMAC_SHA256, jwx.getAlgorithmHeaderValue());
        jwx.setKey(oct256bitJwk.getKey());
        Assert.assertEquals(oct256bitJwk.getKeyId(), jwx.getKeyIdHeaderValue());
        jwx.getPayload();
    }

    @Test
    public void jwe1() throws JoseException
    {
        String cs = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiOWVyIn0." +
                "." +
                "XAog2l7TP5-0mIPYjT2ZYg." +
                "Zf6vQZhxeAfzk2AyuXsKJSo1R8aluPDvK7a6N7wvSmuIUczDhUtJFmNdXC3d4rPa." +
                "XBTguLfGeGKu6YsQVnes2w";
        JsonWebStructure jwx = JsonWebStructure.fromCompactSerialization(cs);
        jwx.setKey(oct256bitJwk.getKey());
        Assert.assertTrue(cs + " should give a JWE " + jwx, jwx instanceof JsonWebEncryption);
        Assert.assertEquals(KeyManagementAlgorithmIdentifiers.DIRECT, jwx.getAlgorithmHeaderValue());
        Assert.assertEquals(oct256bitJwk.getKeyId(), jwx.getKeyIdHeaderValue());
        String payload = jwx.getPayload();
        Assert.assertEquals(YOU_LL_GET_NOTHING_AND_LIKE_IT, payload);
    }

    @Test
    public void jwe2() throws JoseException
    {
        String cs = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiOWVyIn0." +
                "RAqGCBMFk7O-B-glFckcFmxUr8BTTXuZk-bXAdRZxpk5Vgs_1yoUQw." +
                "hyl68_ADlK4VRDYiQMQS6w." +
                "xk--JKIVF4Xjxc0gRGPL30s4PSNtj685WYqXbjyItG0uSffD4ajGXdz4BO8i0sbM." +
                "WXaAVpBgftXyO1HkkRvgQQ";
        JsonWebStructure jwx = JsonWebStructure.fromCompactSerialization(cs);
        jwx.setKey(oct256bitJwk.getKey());
        Assert.assertTrue(cs + " should give a JWE " + jwx, jwx instanceof JsonWebEncryption);
        Assert.assertEquals(KeyManagementAlgorithmIdentifiers.A256KW, jwx.getAlgorithmHeaderValue());
        Assert.assertEquals(oct256bitJwk.getKeyId(), jwx.getKeyIdHeaderValue());
        String payload = jwx.getPayload();
        Assert.assertEquals(YOU_LL_GET_NOTHING_AND_LIKE_IT, payload);
    }

    @Test (expected = IntegrityException.class)
    public void integrityCheckFailsJwe() throws JoseException
    {
        String cs = "eyJhbGciOiJBMjU2S1ciLCJlbmMiOiJBMTI4Q0JDLUhTMjU2Iiwia2lkIjoiOWVyIn0." +
                "RAqGCBMFk7O-B-glFckcFmxUr8BTTXuZk-bXAdRZxpk5Vgs_1yoUQw." +
                "hyl68_ADlK4VRDYiQMQS6w." +
                "xk--JKIVF4Xjxc0gRGPL30s4PSNtj685WYqXbjyItG0uSffD4ajGXdz4BO8i0sbM." +
                "aXaAVpBgftxqO1HkkRvgab";
        JsonWebStructure jwx = JsonWebStructure.fromCompactSerialization(cs);
        jwx.setKey(oct256bitJwk.getKey());
        Assert.assertTrue(cs + " should give a JWE " + jwx, jwx instanceof JsonWebEncryption);
        Assert.assertEquals(KeyManagementAlgorithmIdentifiers.A256KW, jwx.getAlgorithmHeaderValue());
        Assert.assertEquals(oct256bitJwk.getKeyId(), jwx.getKeyIdHeaderValue());
        jwx.getPayload();
    }

    @Test (expected = JoseException.class)
    public void testFromInvalidCompactSerialization1() throws Exception
    {
        JsonWebStructure.fromCompactSerialization("blah.blah.blah.blah");
    }

    @Test (expected = JoseException.class)
    public void testFromInvalidCompactSerialization2() throws Exception
    {
        JsonWebStructure.fromCompactSerialization("nope");
    }

    @Test (expected = JoseException.class)
    public void testFromInvalidCompactSerialization3() throws Exception
    {
        JsonWebStructure.fromCompactSerialization("blah.blah.blah.blah.too.darn.many");
    }

    @Test (expected = JoseException.class)
    public void testFromInvalidCompactSerialization4() throws Exception
    {
        JsonWebStructure.fromCompactSerialization("eyJhbGciOiJIUzI1NiJ9." +
                "." +
                "c29tZSBjb250ZW50IHRoYXQgaXMgdGhlIHBheWxvYWQ." +
                "qGO7O7W2ECVl6uO7lfsXDgEF-EUEti0i-a_AimulIRA");
    }

    @Test
    public void testCertificateChain() throws CertificateException, JoseException
    {
        // sample taken form https://tools.ietf.org/html/rfc7515#appendix-B
        String pem = "MIIE3jCCA8agAwIBAgICAwEwDQYJKoZIhvcNAQEFBQAwYzELMAkGA1UEBhMCVVM" +
                "xITAfBgNVBAoTGFRoZSBHbyBEYWRkeSBHcm91cCwgSW5jLjExMC8GA1UECxMoR2" +
                "8gRGFkZHkgQ2xhc3MgMiBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eTAeFw0wNjExM" +
                "TYwMTU0MzdaFw0yNjExMTYwMTU0MzdaMIHKMQswCQYDVQQGEwJVUzEQMA4GA1UE" +
                "CBMHQXJpem9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTEaMBgGA1UEChMRR29EYWR" +
                "keS5jb20sIEluYy4xMzAxBgNVBAsTKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYW" +
                "RkeS5jb20vcmVwb3NpdG9yeTEwMC4GA1UEAxMnR28gRGFkZHkgU2VjdXJlIENlc" +
                "nRpZmljYXRpb24gQXV0aG9yaXR5MREwDwYDVQQFEwgwNzk2OTI4NzCCASIwDQYJ" +
                "KoZIhvcNAQEBBQADggEPADCCAQoCggEBAMQt1RWMnCZM7DI161+4WQFapmGBWTt" +
                "wY6vj3D3HKrjJM9N55DrtPDAjhI6zMBS2sofDPZVUBJ7fmd0LJR4h3mUpfjWoqV" +
                "Tr9vcyOdQmVZWt7/v+WIbXnvQAjYwqDL1CBM6nPwT27oDyqu9SoWlm2r4arV3aL" +
                "GbqGmu75RpRSgAvSMeYddi5Kcju+GZtCpyz8/x4fKL4o/K1w/O5epHBp+YlLpyo" +
                "7RJlbmr2EkRTcDCVw5wrWCs9CHRK8r5RsL+H0EwnWGu1NcWdrxcx+AuP7q2BNgW" +
                "JCJjPOq8lh8BJ6qf9Z/dFjpfMFDniNoW1fho3/Rb2cRGadDAW/hOUoz+EDU8CAw" +
                "EAAaOCATIwggEuMB0GA1UdDgQWBBT9rGEyk2xF1uLuhV+auud2mWjM5zAfBgNVH" +
                "SMEGDAWgBTSxLDSkdRMEXGzYcs9of7dqGrU4zASBgNVHRMBAf8ECDAGAQH/AgEA" +
                "MDMGCCsGAQUFBwEBBCcwJTAjBggrBgEFBQcwAYYXaHR0cDovL29jc3AuZ29kYWR" +
                "keS5jb20wRgYDVR0fBD8wPTA7oDmgN4Y1aHR0cDovL2NlcnRpZmljYXRlcy5nb2" +
                "RhZGR5LmNvbS9yZXBvc2l0b3J5L2dkcm9vdC5jcmwwSwYDVR0gBEQwQjBABgRVH" +
                "SAAMDgwNgYIKwYBBQUHAgEWKmh0dHA6Ly9jZXJ0aWZpY2F0ZXMuZ29kYWRkeS5j" +
                "b20vcmVwb3NpdG9yeTAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQEFBQADggE" +
                "BANKGwOy9+aG2Z+5mC6IGOgRQjhVyrEp0lVPLN8tESe8HkGsz2ZbwlFalEzAFPI" +
                "UyIXvJxwqoJKSQ3kbTJSMUA2fCENZvD117esyfxVgqwcSeIaha86ykRvOe5GPLL" +
                "5CkKSkB2XIsKd83ASe8T+5o0yGPwLPk9Qnt0hCqU7S+8MxZC9Y7lhyVJEnfzuz9" +
                "p0iRFEUOOjZv2kWzRaJBydTXRE4+uXR21aITVSzGh6O1mawGhId/dQb8vxRMDsx" +
                "uxN89txJx9OjxUUAiKEngHUuHqDTMBqLdElrRhjZkAzVvb3du6/KFUJheqwNTrZ" +
                "EjYx8WnM25sgVjOuH0aBsXBTWVU+4=";
        byte[] der = Base64.decode(pem);

        Certificate cert = CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(der));
        JsonWebSignature jws = new JsonWebSignature();
        jws.setPayload("something to fill the emptiness...");
        jws.setAlgorithmConstraints(AlgorithmConstraints.NO_CONSTRAINTS);
        jws.setAlgorithmHeaderValue(AlgorithmIdentifiers.NONE);
        jws.setCertificateChain((X509Certificate) cert);

        Map<String, Object> headers = JsonUtil.parseJson(jws.headers.getFullHeaderAsJsonString());
        Assert.assertTrue(headers.get("x5c") instanceof List);
        Assert.assertEquals(pem, ((List) headers.get("x5c")).get(0));

        // also check the getter
        List<X509Certificate> certChain = jws.getCertificateChain();
        Assert.assertEquals(1, certChain.size());
        Assert.assertEquals(cert, certChain.get(0));

        // check that we can retrieve the certificate chain after deserialization
        String compactSerialization = jws.getCompactSerialization();
        JsonWebSignature anotherJws = new JsonWebSignature();
        anotherJws.setCompactSerialization(compactSerialization);
        Assert.assertEquals(cert, anotherJws.getLeafCertificate());
    }

    @Test
    public void testEmptyCertificateChain() throws Exception
    {
        String cs = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjllciJ9." +
                "WW91J2xsIGdldCBub3RoaW5nLCBhbmQgbGlrZSBpdCE." +
                "45s_xV_ol7JBwVcTPbWbaYT5i4mb7j27lEhi_bxpExw";
        JsonWebStructure jwx = JsonWebStructure.fromCompactSerialization(cs);

        Assert.assertNull(jwx.getCertificateChain());
        Assert.assertNull(jwx.getLeafCertificate());
    }
}
