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
        <version>3.2.2</version>
    </dependency>
```    
