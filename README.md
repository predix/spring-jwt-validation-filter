# spring-jwt-validation-filter

This module provides two implementations of org.springframework.security.oauth2.provider.token.ResourceServerTokenServices
for loading spring authentication based on a access token in a incoming request.

## LICENSE
This project is licensed under Apache v2.

# FastTokenServices 
FastTokenServices is a replacement for the original RemoteTokenServices. It is "fast" because it does not make calls 
to UAA’s /check_token endpoint every time it verifies a token. Instead, it uses UAA’s token signing key, fetched at 
startup, to verify the token.

## Usage    
To use FastTokenServices, update spring config and specify an exact list of trusted issuers. 
The bean settings will look like follow:

```xml
    <oauth:resource-server id="oauth2remoteTokenFilter"      token-services-ref="tokenServices" />
            
    <bean id="tokenServices" class="com.ge.predix.uaa.token.lib.FastTokenServices">
        <property name="storeClaims" value="true" />
        <util:list id="trustedIssuers" value-type="java.lang.String">
            <value>https://testzone1.localhost/uaa/oauth/token</value>
            <value>https://testzone2.localhost/uaa/oauth/token</value>
        </util:list>
    </bean>
```

# ZacTokenService

This implementation of ResourceServerTokenServices is meant for services which use ZAC for zone authorization of 
requests. This services handles authentication based on the specific zone being accessed in the request and consults
ZAC for information needed on the token issuers trusted for that zone.

## Usage
```xml
    <oauth:resource-server id="oauth2remoteTokenFilter"      token-services-ref="zacTokenServices" />
        
    <bean id="zacTokenServices" class="com.ge.predix.uaa.token.lib.ZacTokenService">
        <property name="serviceId" value="<ZAC_SERVICE_ID>" />
        <property name="zacUrl" value="${ZAC_URL}" />
        <property name="defaultZoneConfig" ref="acsDefaultZoneConfig" />
        <property name="oauth2RestTemplate" ref="zacRestTemplate" />
    </bean>

    <bean id="acsDefaultZoneConfig" class="com.ge.predix.uaa.token.lib.DefaultZoneConfiguration">
        <property name="trustedIssuerId" value="${ACS_DEFAULT_ISSUER_ID}" />
        <property name="allowedUriPatterns">
            <list>
                <value>/v1/zone/**</value>
            </list>
        </property>
    </bean>
    
        <bean id="zacRestTemplate"
        class="org.springframework.security.oauth2.client.OAuth2RestTemplate">
        <constructor-arg>
            <bean
                class="org.springframework.security.oauth2.client.token.grant.client.ClientCredentialsResourceDetails">
                <property name="accessTokenUri" value="${ZAC_UAA_TOKENURL}" />
                <property name="clientId" value="${ZAC_CLIENT_ID}" />
                <property name="clientSecret" value="${ZAC_CLIENT_SECRET}" />
            </bean>
        </constructor-arg>
    </bean>
```


# Maven Dependency
```xml
    <dependency>
        <groupId>com.ge.predix</groupId>
        <artifactId>uaa-token-lib</artifactId>
        <version>3.1.4-SNAPSHOT</version>
    </dependency>
```    
