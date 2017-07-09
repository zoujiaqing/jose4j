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

package org.jose4j.jws;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmFactory;
import org.jose4j.jwa.AlgorithmFactoryFactory;
import org.jose4j.jwx.CompactSerializer;
import org.jose4j.jwx.HeaderParameterNames;
import org.jose4j.jwx.JsonWebStructure;
import org.jose4j.keys.KeyPersuasion;
import org.jose4j.lang.IntegrityException;
import org.jose4j.lang.InvalidAlgorithmException;
import org.jose4j.lang.JoseException;
import org.jose4j.lang.StringUtil;

import java.security.Key;

/**
 * The JsonWebSignature class is used to produce and consume JSON Web Signature (JWS) as defined in
 * RFC 7515.
 */
public class JsonWebSignature extends JsonWebStructure
{
    public static final short COMPACT_SERIALIZATION_PARTS = 3;

    private byte[] payloadBytes;
    private String payloadCharEncoding = StringUtil.UTF_8;
    private String encodedPayload;

    private Boolean validSignature;

    public JsonWebSignature()
    {
        if (!Boolean.getBoolean("org.jose4j.jws.default-allow-none"))
        {
            setAlgorithmConstraints(AlgorithmConstraints.DISALLOW_NONE);
        }
    }

    /**
     * Sets the JWS payload as a string.
     * Use {@link #setPayloadCharEncoding(String)} before calling this method, to use a character
     * encoding other than UTF-8.
     * @param payload the payload, as a string, to be singed.
     */
    public void setPayload(String payload)
    {
        this.payloadBytes = StringUtil.getBytesUnchecked(payload, payloadCharEncoding);
    }

    /**
     * Get the JWS payload.
     * @return the sequence of bytes that make up the JWS payload.
     * @throws JoseException if the JWS signature is invalid or an error condition is encountered during the signature verification process
     */
    public byte[] getPayloadBytes() throws JoseException
    {
        if (!verifySignature())
        {
            throw new IntegrityException("JWS signature is invalid.");
        }

        return payloadBytes;
    }

    /**
     * Get the JWS payload. Unlike {@link #getPayloadBytes()} the signature is not
     * verified when calling this method.
     * @return the sequence of bytes that make up the JWS payload.
     */
    public byte[] getUnverifiedPayloadBytes()
    {
        return payloadBytes;
    }


    /**
     * Sets the JWS payload.
     * @param payloadBytes the payload, as a byte array, to be singed
     */
    public void setPayloadBytes(byte[] payloadBytes)
    {
        this.payloadBytes = payloadBytes;
    }

    protected void setCompactSerializationParts(String[] parts) throws JoseException
    {
        if (parts.length != COMPACT_SERIALIZATION_PARTS)
        {
            throw new JoseException("A JWS Compact Serialization must have exactly "+COMPACT_SERIALIZATION_PARTS+" parts separated by period ('.') characters");
        }

        setEncodedHeader(parts[0]);
        setEncodedPayload(parts[1]);
        setSignature(base64url.base64UrlDecode(parts[2]));
    }

    /**
     * <p>
     * Sign and produce the JWS Compact Serialization.
     * </p>
     * <p>
     * The JWS Compact Serialization represents digitally signed or MACed
     * content as a compact, URL-safe string.  This string is:
     * <p>
     * BASE64URL(UTF8(JWS Protected Header)) || '.' ||
     * BASE64URL(JWS Payload) || '.' ||
     * BASE64URL(JWS Signature)
     * </p>
     * @return the Compact Serialization: the encoded header + "." + the encoded payload + "." + the encoded signature
     * @throws JoseException
     */
    public String getCompactSerialization() throws JoseException
    {
        this.sign();
        return CompactSerializer.serialize(getSigningInput(), getEncodedSignature());
    }

    /**
     * Produces the compact serialization with an empty/detached payload as described in
     * <a href="http://tools.ietf.org/html/rfc7515#appendix-F">Appendix F, Detached Content, of the JWS spec</a>
     * though providing library support rather than making the application do it all as
     * described therein.
     *
     * @return the encoded header + ".." + the encoded signature
     * @throws JoseException if an error condition is encountered during the signing process
     */
    public String getDetachedContentCompactSerialization() throws JoseException
    {
        this.sign();
        return CompactSerializer.serialize(getEncodedHeader(), "", getEncodedSignature());
    }

    /**
     * Compute the JWS signature.
     * @throws JoseException if an error condition is encountered during the signing process
     */
    public void sign() throws JoseException
    {
        JsonWebSignatureAlgorithm algorithm = getAlgorithm();
        Key signingKey = getKey();
        if (isDoKeyValidation())
        {
            algorithm.validateSigningKey(signingKey);
        }
        byte[] inputBytes = getSigningInputBytes();
        byte[] signatureBytes = algorithm.sign(signingKey, inputBytes, getProviderCtx());
        setSignature(signatureBytes);
    }

    @Override
    protected void onNewKey()
    {
        validSignature = null;
    }

    /**
     * Verify the signature of the JWS.
     * @return true if the signature is valid, false otherwise
     * @throws JoseException if an error condition is encountered during the signature verification process
     */
    public boolean verifySignature() throws JoseException
    {
        JsonWebSignatureAlgorithm algorithm = getAlgorithm();
        Key verificationKey = getKey();
        if (isDoKeyValidation())
        {
            algorithm.validateVerificationKey(verificationKey);
        }
        if (validSignature == null)
        {
            checkCrit();
            byte[] signatureBytes = getSignature();
            byte[] inputBytes = getSigningInputBytes();
            validSignature = algorithm.verifySignature(signatureBytes, verificationKey, inputBytes, getProviderCtx());
        }

        return validSignature;
    }

    @Override
    public JsonWebSignatureAlgorithm getAlgorithm() throws InvalidAlgorithmException
    {
        return getAlgorithm(true);
    }

    @Override
    public JsonWebSignatureAlgorithm getAlgorithmNoConstraintCheck() throws InvalidAlgorithmException
    {
        return getAlgorithm(false);
    }

    private JsonWebSignatureAlgorithm getAlgorithm(boolean checkConstraints) throws InvalidAlgorithmException
    {
        String algo = getAlgorithmHeaderValue();
        if (algo == null)
        {
            throw new InvalidAlgorithmException("Signature algorithm header ("+HeaderParameterNames.ALGORITHM+") not set.");
        }

        if (checkConstraints)
        {
            getAlgorithmConstraints().checkConstraint(algo);
        }

        AlgorithmFactoryFactory factoryFactory = AlgorithmFactoryFactory.getInstance();
        AlgorithmFactory<JsonWebSignatureAlgorithm> jwsAlgorithmFactory = factoryFactory.getJwsAlgorithmFactory();
        return jwsAlgorithmFactory.getAlgorithm(algo);
    }

    private byte[] getSigningInputBytes() throws JoseException
    {
        String signingInput = getSigningInput();
        return StringUtil.getBytesAscii(signingInput);
    }

    private String getSigningInput() throws JoseException
    {
        return CompactSerializer.serialize(getEncodedHeader(), getEncodedPayload());
    }

    /**
     * Gets the JWS payload as a string.
     * Use {@link #setPayloadCharEncoding(String)} before calling this method, to use a character
     * encoding other than UTF-8.
     * @return the JWS payload
     * @throws JoseException if the JWS signature is invalid or an error condition is encountered during the signature verification process
     */
    public String getPayload() throws JoseException
    {
        if (!Boolean.getBoolean("org.jose4j.jws.getPayload-skip-verify") && !verifySignature())
        {
            throw new IntegrityException("JWS signature is invalid.");
        }
        return getStringPayload();
    }

    /**
     * Gets the JWS payload as a string. Unlike {@link #getPayload()} the signature is not
     * verified when calling this method.
     * Use {@link #setPayloadCharEncoding(String)} before calling this method, to use a character
     * encoding other than UTF-8.
     */
    public String getUnverifiedPayload()
    {
        return getStringPayload();
    }

    private String getStringPayload()
    {
        return StringUtil.newString(payloadBytes, payloadCharEncoding);
    }

    /**
     * Gets the character encoding used for the string representation of the JWS payload.
     * The default encoding is UTF-8.
     * @return the character encoding
     */
    public String getPayloadCharEncoding()
    {
        return payloadCharEncoding;
    }

    /**
     * Sets the character encoding used for the string representation of the JWS payload (i.e.
     * when using {@link #getPayload()}, {@link #getUnverifiedPayload()}, or {@link #setPayload(String)}).
     * The default encoding is UTF-8.
     * @param payloadCharEncoding the character encoding to use for the string representation of the JWS payload
     */
    public void setPayloadCharEncoding(String payloadCharEncoding)
    {
        this.payloadCharEncoding = payloadCharEncoding;
    }

    public String getKeyType() throws InvalidAlgorithmException
    {
        return getAlgorithmNoConstraintCheck().getKeyType();
    }

    public KeyPersuasion getKeyPersuasion() throws InvalidAlgorithmException
    {
        return getAlgorithmNoConstraintCheck().getKeyPersuasion();
    }

    public void setEncodedPayload(String encodedPayload)
    {
        this.encodedPayload = encodedPayload;
        this.payloadBytes = base64url.base64UrlDecode(encodedPayload);
    }

    /**
     * Gets the base64url encoded JWS Payload.
     * @return the base64url encoded JWS Payload.
     */
    public String getEncodedPayload()
    {
        return (encodedPayload != null) ? encodedPayload : base64url.base64UrlEncode(payloadBytes);
    }

    public String getEncodedSignature()
    {
        return base64url.base64UrlEncode(getSignature());
    }

    protected byte[] getSignature()
    {
        return getIntegrity();
    }

    protected void setSignature(byte[] signature)
    {
        setIntegrity(signature);
    }
}
