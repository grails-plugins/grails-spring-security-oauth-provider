/* Copyright 2006-2010 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the 'License');
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an 'AS IS' BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
security {
	oauthProvider {
		require10a = true
		requestTokenFilter {
			filterProcessesUrl = '/oauth_request_token'
			ignoreMissingCredentials = false
			allowedMethods = ['GET', 'POST']
			responseContentType = 'text/plain;charset=utf-8'
		}
		entryPoint {
			realmName = 'Grails OAuth Provider' // should be changed
		}
		nonce {
			validityWindowSeconds = 60 * 60 * 12 // 12 hrs
		}
		provider {
			baseUrl = null
		}
		signature {
			supportPlainText = false
			supportHMAC_SHA1 = true
			supportRSA_SHA1 = true
		}
		tokenServices {
			tokenSecretLengthBytes = 80
			requestTokenValiditySeconds = 60 * 10 //default 10 minutes
			accessTokenValiditySeconds = 60 * 60 * 12 //default 12 hours
		}
		authTokenFilter {
			filterProcessesUrl = '/oauth_authenticate_token'
			tokenIdParameterName = 'requestToken'
		}
		verifier {
			lengthBytes = 6
		}
		successHandler {
			tokenIdParameterName = 'requestToken'
			callbackParameterName = 'callbackURL'
		}
		accessTokenFilter {
			filterProcessesUrl = '/oauth_access_token'
			ignoreMissingCredentials = false
			allowedMethods = ['GET', 'POST']
		}
		protectedResourceFilter {
			allowAllMethods = true
			ignoreMissingCredentials = true
		}
	}
}
