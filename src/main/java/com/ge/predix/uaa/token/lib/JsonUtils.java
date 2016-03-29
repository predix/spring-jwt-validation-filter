/*******************************************************************************
 *     Cloud Foundry
 *     Copyright 2009, 2016-2015] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package com.ge.predix.uaa.token.lib;

import java.io.IOException;

import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public final class JsonUtils {
    private static ObjectMapper objectMapper = new ObjectMapper();

    private JsonUtils() {
        //prevent instantiation
    }

    public static String writeValueAsString(final Object object) throws JsonUtilException {
        try {
            return objectMapper.writeValueAsString(object);
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static byte[] writeValueAsBytes(final Object object) throws JsonUtilException {
        try {
            return objectMapper.writeValueAsBytes(object);
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static <T> T readValue(final String s, final Class<T> clazz) throws JsonUtilException {
        try {
            if (StringUtils.hasText(s)) {
                return objectMapper.readValue(s, clazz);
            } else {
                return null;
            }
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static <T> T readValue(final String s, final TypeReference<?> typeReference) {
        try {
            if (StringUtils.hasText(s)) {
                return objectMapper.readValue(s, typeReference);
            } else {
                return null;
            }
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static <T> T convertValue(final Object object, final Class<T> toClazz) throws JsonUtilException {
        try {
            if (object == null) {
                return null;
            } else {
                return objectMapper.convertValue(object, toClazz);
            }
        } catch (IllegalArgumentException e) {
            throw new JsonUtilException(e);
        }
    }

    public static JsonNode readTree(final String s) {
        try {
            if (StringUtils.hasText(s)) {
                return objectMapper.readTree(s);
            } else {
                return null;
            }
        } catch (JsonProcessingException e) {
            throw new JsonUtilException(e);
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static class JsonUtilException extends RuntimeException {

        private static final long serialVersionUID = -4804245225960963421L;

        public JsonUtilException(final Throwable cause) {
            super(cause);
        }

    }

}
