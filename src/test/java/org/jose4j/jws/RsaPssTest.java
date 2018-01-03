package org.jose4j.jws;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.JceProviderTestSupport;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.keys.ExampleRsaKeyFromJws;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

import static org.hamcrest.CoreMatchers.allOf;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;

/**
 *
 */
public class RsaPssTest
{
    private final String[] pssAlgs = new String[]{AlgorithmIdentifiers.RSA_PSS_USING_SHA256,
            AlgorithmIdentifiers.RSA_PSS_USING_SHA384, AlgorithmIdentifiers.RSA_PSS_USING_SHA512};

    @Test
    public void roundTrip() throws Exception
    {


        JceProviderTestSupport jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setSignatureAlgsNeeded(pssAlgs);
        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {
                for (String alg : pssAlgs)
                {
                    JsonWebSignature jws = new JsonWebSignature();
                    jws.setAlgorithmHeaderValue(alg);
                    String payload = "stuff here";
                    jws.setPayload(payload);
                    jws.setKey(ExampleRsaKeyFromJws.PRIVATE_KEY);

                    String cs = jws.getCompactSerialization();

                    System.out.println(cs);

                    jws = new JsonWebSignature();
                    jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, alg));
                    jws.setKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
                    jws.setCompactSerialization(cs);

                    assertTrue(jws.verifySignature());
                    assertThat(payload, equalTo(jws.getPayload()));


                }
            }
        });
    }

    @Test
    public void testSomeVerifies() throws Exception
    {
        final List<String> jwss = new ArrayList<>();

        // created using BC provider with PSSParameterSpec
        jwss.add("eyJhbGciOiJQUzI1NiJ9.c3R1ZmYgaGVyZQ.KaRX4zjLPIoT0AAK2YZ9deKyE28pZnTBS-dOaANNxpdlDrc5El99xlOD18qbPpwZDSx0iGdRTdm078LZRO6O6VRxOS9sFJl_iau-LDtHT5rPpk0BiJOH6uWE_Dr2qttdOlHaL9FwJdYJSi5Oy6BwkFulfjRMvC2i5g62FEJ4HndeIqKgCA5miwni6erjQKbN_A58_HA664uGKHziUkCzNJPQo7xcODFo1UMJflBYxMjAG6q5J-wzCX2usoWk5KrPBovEOJHAL5hw1lQJ6NV0NRBKB6ND1mYZiLzyvEIVoUYqa3C_sXaXTfjZ7jCR0EJUX7FjzaIHamnErZZpL8nZDQ");
        jwss.add("eyJhbGciOiJQUzM4NCJ9.c3R1ZmYgaGVyZQ.XDsnCIxKsZy_Te8nToIcRvCskGE5J7sUFpYE_MflcEIZ5NLgT9SBpmLvEl9IfsJyoMxk9yH4__F5Cvl3bjcBQ8UCk4yW-P8J8MFVanyeCwtjAtwJl1So-W_Zd3DG-QpKlVaak9xE_-glgv7yNAAaRMHRrqDr1fwUnqDA7rjwq4OY_4kZh5j0Pesna6A0MAnQJusPEQUpjFN1DWzzS-f20TPoLlm-4CzXE60X8DRLs3EzeJA0SPWdOcYosikg_yZdu3HzDWL-8Cs81gbXLZLqsf2CaPakunRouOcnCSRkYhrcwv2FFxlnV29ivNWpLzjSrhplHu99d1R-xT2ZIFJ91w");
        jwss.add("eyJhbGciOiJQUzUxMiJ9.c3R1ZmYgaGVyZQ.FZqQotC88S8E6pB08NEfIvrdwimHQAQACUWC7eBJOfSkZa52i1R2nRfI4CmcG3lEzMuYKsmREVysoDGTJWX5_X49-8Yilnq4hNBG2BN1nXwD3agRHmDNw0Pz8GgpjmK-LMcNZxSPtnLq0KnFtq1miOogFgg3xjaI21MIC0hzaE8DCvz1X82dLm_oVapjx4UivARTruME0T_4pcLsZViTkAmsg0Uu_bMOv3VWQLc-sZAl7rRPUa_dWTcAuBToPOcuxK0b6ZiM2akkDuGjbmVHEJNaKmcjWNOl0Gj6wJg5Q2R4wboKP6NxaIs2tpf1qaolVZ2COcnmGGl10kmmIVHKXw");

        // created using BC provider without PSSParameterSpec (that seems to end up using defaults that are the same)
        jwss.add("eyJhbGciOiJQUzI1NiJ9.c3R1ZmYgaGVyZQ.WWqFutYS09AWi2K1KX-rix_yrwTgt2urJz1ZVVAHSzGLFio9WR_L6qockPFKnhmISWvN1FLmOgOLBJv9YmlUobH0ktNEXg7B03chRAt9vMgvhilExYzA_scnlOI9ZRBoThZ9TS7GazLX-NoFL9w4imm1MQkFgknkUaKHJK62VNeQZTQXqubIGw28g2SkMPU-J03mW5wM-3yK3wNgzcW_3VJyDGdnNnkVMu4o1Za17zlzxJxCVHkBih2nLCqiPO7OPrSEnq5F6pw6V4PN1UGQz9aKRy_IgnEvNxI6y8JDRDSWSf80rYHCvfbUVbrP7H-COWc_VpplgXY9_vnX6_GX0w");
        jwss.add("eyJhbGciOiJQUzM4NCJ9.c3R1ZmYgaGVyZQ.eOrEcpfGhsBuBjvwUQNp8KEyJiQuNbmRbYLTAnlCtkScUb7ZSBqe7mlDyaym8uOHHkedhuwz-5BDlbWzkZ7ISgUNm2g6e3xS-nhVnOr8ttWQ7dpsQeSspxohKafZfg6rAcyYrsljf41hhQfVVv-PBNe5fxEq8DKC-h3xFil4LmZ5XEEeMSlAo5tU8g-BsWRpVk7qhXIncRHFsCPPBjN7gu-OU-JHCLkNdkp9wW1MJuLXUduKnP1aXW7FZji7ZyzQYXvpVA5vUAdFY9Zz_cM0QppwiaPew66D_LfaSKwzSMB55nAc6gvpDfP_D3iAlrT47ZBofvPjYQejKdN4WK1_Tg");
        jwss.add("eyJhbGciOiJQUzUxMiJ9.c3R1ZmYgaGVyZQ.e6twRBcgDBYw8vw_Lqn0w9v-MiD5Tr8ovCMvlezeUt829zvgP2_9oY-azvHr6f15B9w7ehLFJt4nbBUuOMt4IrsEDxAB3puLA7bsHJCfE-2vNC6QrkG3uPDqPRGPGSL30gDUAOL3y6WHsXuAckDJnEgtAQsLWHi8ctiDt_9-jfskL0uimEoWhThsThjI9vKp0QuQO2Bw_c0Y7BcbTzNU1DP3FEtUJT-je0d7K8TrKaidzRRqOykvNbfcad6w29xg0PQYb7ImfWY7FxCIBUpFkHJT4HR4upJ6aEVS9SojB-tAM9jqiW5OI9ABHQE0ZUYcbPdR1xKG3nGcCx36YVQy3Q");
        
        JceProviderTestSupport jceProviderTestSupport = new JceProviderTestSupport();
        jceProviderTestSupport.setSignatureAlgsNeeded(pssAlgs);
        jceProviderTestSupport.runWithBouncyCastleProviderIfNeeded(new JceProviderTestSupport.RunnableTest()
        {
            @Override
            public void runTest() throws Exception
            {
                for (String cs : jwss)
                {
                    JsonWebSignature jws = new JsonWebSignature();
                    jws.setAlgorithmConstraints(new AlgorithmConstraints(AlgorithmConstraints.ConstraintType.WHITELIST, pssAlgs));
                    jws.setKey(ExampleRsaKeyFromJws.PUBLIC_KEY);
                    jws.setCompactSerialization(cs);

                    assertTrue(jws.verifySignature());
                    assertThat("stuff here", equalTo(jws.getPayload()));
                }
            }
        });
    }
}
