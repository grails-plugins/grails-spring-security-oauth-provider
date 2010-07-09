/* Copyright 2006-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import org.codehaus.groovy.grails.plugins.springsecurity.SecurityFilterPosition
import org.codehaus.groovy.grails.plugins.springsecurity.SpringSecurityUtils

import org.springframework.security.oauth.common.signature.CoreOAuthSignatureMethodFactory
import org.springframework.security.oauth.provider.AccessTokenProcessingFilter
import org.springframework.security.oauth.provider.CoreOAuthProviderSupport
import org.springframework.security.oauth.provider.DefaultAuthenticationHandler
import org.springframework.security.oauth.provider.InMemoryConsumerDetailsService
import org.springframework.security.oauth.provider.OAuthProcessingFilterEntryPoint
import org.springframework.security.oauth.provider.ProtectedResourceProcessingFilter
import org.springframework.security.oauth.provider.UnauthenticatedRequestTokenProcessingFilter
import org.springframework.security.oauth.provider.UserAuthorizationProcessingFilter
import org.springframework.security.oauth.provider.UserAuthorizationSuccessfulAuthenticationHandler
import org.springframework.security.oauth.provider.nonce.ExpiringTimestampNonceServices
import org.springframework.security.oauth.provider.token.InMemoryProviderTokenServices
import org.springframework.security.oauth.provider.token.OAuthTokenLifecycleRegistryPostProcessor
import org.springframework.security.oauth.provider.verifier.RandomValueVerifierServices

class SpringSecurityOauthProviderGrailsPlugin {

	String version = '0.1'
	String grailsVersion = '1.2.2 > *'
	Map dependsOn = ['springSecurityCore': '0.4 > *']

	List pluginExcludes = [
		'docs/**',
		'src/docs/**'
	]

	String author = 'Burt Beckwith'
	String authorEmail = 'beckwithb@vmware.com'
	String title = 'OAuth Provider support for the Spring Security plugin.'
	String description = 'OAuth Provider support for the Spring Security plugin.'

	String documentation = 'http://grails.org/plugin/spring-security-oauth-provider'

	def doWithSpring = {

		def conf = SpringSecurityUtils.securityConfig
		if (!conf || !conf.active) {
			return
		}

		println 'Configuring Spring Security OAuth Provider ...'

		SpringSecurityUtils.loadSecondaryConfig 'DefaultOAuthProviderSecurityConfig'
		// have to get again after overlaying DefaultOAuthProviderSecurityConfig
		conf = SpringSecurityUtils.securityConfig

		SpringSecurityUtils.registerFilter 'oauthRequestTokenFilter',
				SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order + 1
		SpringSecurityUtils.registerFilter 'oauthAuthenticateTokenFilter',
				SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order + 2
		SpringSecurityUtils.registerFilter 'oauthAccessTokenFilter',
				SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order + 3
		SpringSecurityUtils.registerFilter 'oauthProtectedResourceFilter',
				SecurityFilterPosition.EXCEPTION_TRANSLATION_FILTER.order + 4

		oauthAuthenticationEntryPoint(OAuthProcessingFilterEntryPoint) {
			realmName = conf.oauthProvider.entryPoint.realmName
		}

		oauthNonceServices(ExpiringTimestampNonceServices) {
			validityWindowSeconds = conf.oauthProvider.nonce.validityWindowSeconds // 12 hrs
		}

		oauthProviderSupport(CoreOAuthProviderSupport) {
			baseUrl = conf.oauthProvider.provider.baseUrl // null
		}

		oauthSignatureMethodFactory(CoreOAuthSignatureMethodFactory) {
			supportPlainText = conf.oauthProvider.signature.supportPlainText // false
			supportHMAC_SHA1 = conf.oauthProvider.signature.supportHMAC_SHA1 // true
			supportRSA_SHA1 = conf.oauthProvider.signature.supportRSA_SHA1  // true
		}

		oauthConsumerDetailsService(InMemoryConsumerDetailsService)

		oauthTokenServices(InMemoryProviderTokenServices) {
			tokenSecretLengthBytes = conf.oauthProvider.tokenServices.tokenSecretLengthBytes // 80
			requestTokenValiditySeconds = conf.oauthProvider.tokenServices.requestTokenValiditySeconds // 10 minutes
			accessTokenValiditySeconds = conf.oauthProvider.tokenServices.accessTokenValiditySeconds // 12 hours
		}

		oauthRequestTokenFilter(UnauthenticatedRequestTokenProcessingFilter) {
			authenticationEntryPoint = ref('oauthAuthenticationEntryPoint')
			nonceServices = ref('oauthNonceServices')
			providerSupport = ref('oauthProviderSupport')
			signatureMethodFactory = ref('oauthSignatureMethodFactory')
			consumerDetailsService = ref('oauthConsumerDetailsService')
			tokenServices = ref('oauthTokenServices')
			filterProcessesUrl = conf.oauthProvider.requestTokenFilter.filterProcessesUrl // '/oauth_request_token'
			ignoreMissingCredentials = conf.oauthProvider.requestTokenFilter.ignoreMissingCredentials // false
			allowedMethods = conf.oauthProvider.requestTokenFilter.allowedMethods // ['GET', 'POST']
			responseContentType = conf.oauthProvider.requestTokenFilter.responseContentType // 'text/plain;charset=utf-8'
			require10a = conf.oauthProvider.require10a // true
		}

		oauthVerifierServices(RandomValueVerifierServices) {
			verifierLengthBytes = conf.oauthProvider.verifier.lengthBytes // 6
		}

		oauthSuccessfulAuthenticationHandler(UserAuthorizationSuccessfulAuthenticationHandler) {
			tokenIdParameterName = conf.oauthProvider.successHandler.tokenIdParameterName // 'requestToken'
			callbackParameterName = conf.oauthProvider.successHandler.callbackParameterName // 'callbackURL'
			require10a = conf.oauthProvider.require10a // true
		}

		oauthAuthenticateTokenFilter(UserAuthorizationProcessingFilter, '/') { 
			authenticationManager = ref('authenticationManager')
			sessionAuthenticationStrategy = ref('sessionAuthenticationStrategy')
			authenticationSuccessHandler = ref('oauthSuccessfulAuthenticationHandler')
			rememberMeServices = ref('rememberMeServices')
			authenticationDetailsSource = ref('authenticationDetailsSource')
			filterProcessesUrl = conf.oauthProvider.authTokenFilter.filterProcessesUrl // '/oauth_authenticate_token'
			continueChainBeforeSuccessfulAuthentication = conf.apf.continueChainBeforeSuccessfulAuthentication // false
			allowSessionCreation = conf.apf.allowSessionCreation // true
			require10a = conf.oauthProvider.require10a // true
			tokenIdParameterName = conf.oauthProvider.authTokenFilter.tokenIdParameterName // 'requestToken'
			tokenServices = ref('oauthTokenServices')
			verifierServices = ref('oauthVerifierServices')
		}

		oauthAccessTokenFilter(AccessTokenProcessingFilter) {
			authenticationEntryPoint = ref('oauthAuthenticationEntryPoint')
			nonceServices = ref('oauthNonceServices')
			providerSupport = ref('oauthProviderSupport')
			signatureMethodFactory = ref('oauthSignatureMethodFactory')
			consumerDetailsService = ref('oauthConsumerDetailsService')
			tokenServices = ref('oauthTokenServices')
			ignoreMissingCredentials = conf.oauthProvider.accessTokenFilter.ignoreMissingCredentials // false
			allowedMethods = conf.oauthProvider.accessTokenFilter.allowedMethods // ['GET', 'POST']
			require10a = conf.oauthProvider.require10a // true
			filterProcessesUrl = conf.oauthProvider.accessTokenFilter.filterProcessesUrl // '/oauth_access_token'
		}

		oauthAuthenticationHandler(DefaultAuthenticationHandler)

		oauthProtectedResourceFilter(ProtectedResourceProcessingFilter) {
			authenticationEntryPoint = ref('oauthAuthenticationEntryPoint')
			nonceServices = ref('oauthNonceServices')
			providerSupport = ref('oauthProviderSupport')
			signatureMethodFactory = ref('oauthSignatureMethodFactory')
			consumerDetailsService = ref('oauthConsumerDetailsService')
			tokenServices = ref('oauthTokenServices')
			authHandler = ref('oauthAuthenticationHandler')
			ignoreMissingCredentials = conf.oauthProvider.protectedResourceFilter.ignoreMissingCredentials // true
			allowAllMethods = conf.oauthProvider.protectedResourceFilter.allowAllMethods // true
		}

		"_oauthTokenRegistryPostProcessor"(OAuthTokenLifecycleRegistryPostProcessor)
	}
}
