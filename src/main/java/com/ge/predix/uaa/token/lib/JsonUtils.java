/*******************************************************************************
 * Copyright 2017 General Electric Company
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
 *******************************************************************************/

package com.ge.predix.uaa.token.lib;

import java.io.IOException;

import org.springframework.util.StringUtils;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

public final class JsonUtils {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private JsonUtils() {
        //prevent instantiation
    }

    public static String writeValueAsString(final Object object) throws JsonUtilException {
        try {
            return OBJECT_MAPPER.writeValueAsString(object);
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static byte[] writeValueAsBytes(final Object object) throws JsonUtilException {
        try {
            return OBJECT_MAPPER.writeValueAsBytes(object);
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static <T> T readValue(final String s, final Class<T> clazz) throws JsonUtilException {
        try {
            if (StringUtils.hasText(s)) {
                return OBJECT_MAPPER.readValue(s, clazz);
            } else {
                return null;
            }
        } catch (IOException e) {
            throw new JsonUtilException(e);
        }
    }

    public static <T> T readValue(final String s, final TypeReference<T> typeReference) {
        try {
            if (StringUtils.hasText(s)) {
                return OBJECT_MAPPER.readValue(s, typeReference);
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
                return OBJECT_MAPPER.convertValue(object, toClazz);
            }
        } catch (IllegalArgumentException e) {
            throw new JsonUtilException(e);
        }
    }

    public static JsonNode readTree(final String s) {
        try {
            if (StringUtils.hasText(s)) {
                return OBJECT_MAPPER.readTree(s);
            } else {
                return null;
            }
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
