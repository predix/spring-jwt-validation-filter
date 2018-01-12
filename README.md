## LICENSE
This project is licensed under Apache v2.

# FastTokenServices 
This module provides an implementation of `org.springframework.security.oauth2.provider.token.ResourceServerTokenServices`
for loading spring authentication based on a JWT access token in a incoming request.

FastTokenServices is a alternative for `org.springframework.security.oauth2.provider.token.RemoteTokenServices`. 
It is "fast" because it does not make calls to UAA’s /check_token endpoint every time it verifies a token. 
Instead, it caches UAA’s token public key after the first fetch for a defined TTL (see property issuerPublicKeyTTL), to verify the JWT in the request.


## Usage    
To use FastTokenServices, update spring config and specify an exact list of trusted issuers. 
Example bean:

```xml
    <oauth:resource-server id="oauth2remoteTokenFilter"      token-services-ref="tokenServices" />
            
    <bean id="tokenServices" class="com.ge.predix.uaa.token.lib.FastTokenServices">        
        <property name="storeClaims" value="true" />
        <util:list id="trustedIssuers" value-type="java.lang.String">
            <value>https://testzone1.localhost/uaa/oauth/token</value>
            <value>https://testzone2.localhost/uaa/oauth/token</value>
        </util:list>
        <!-- And optionally, to customize issuerPublicKey refresh interval (default is 24 hours)
            <property name="issuerPublicKeyTTL" value="3600000L" />
        -->
    </bean>
```

# Maven Dependency
```xml
    <dependency>
        <groupId>com.ge.predix</groupId>
        <artifactId>uaa-token-lib</artifactId>
        <version>3.3.5</version>
    </dependency>
```    
