package edu.ohio.ais.rundeck.util;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import com.fasterxml.jackson.databind.JsonNode;

public class OAuthClient_New extends OAuthClient {

	protected static final Log log = LogFactory.getLog(OAuthClient_New.class);
	public static final String FIELD_SCOPE = "scope";
	public static final String FIELD_CLIENT_ID = "client_id";
	public static final String FIELD_CLIENT_SECRET = "client_secret";
	ScopeType scopeType;

	public OAuthClient_New(GrantType grantType, ScopeType scopeType) {
		super(grantType);
		this.scopeType = scopeType;
	}

	public enum ScopeType {
		INTERNAL_SERVICES
	}

	void doTokenRequest() throws HttpResponseException, OAuthException, IOException {
		this.accessToken = null;

		log.debug("***************Requesting access token from " + this.tokenEndpoint);

		List<NameValuePair> params = new ArrayList<>();
		params.add(new BasicNameValuePair(FIELD_GRANT_TYPE, this.grantType.name().toLowerCase()));
		if (this.scopeType != null) {
			params.add(new BasicNameValuePair(FIELD_SCOPE, this.scopeType.name().toLowerCase()));
		}
		params.add(new BasicNameValuePair(FIELD_CLIENT_ID, this.clientId));
		params.add(new BasicNameValuePair(FIELD_CLIENT_SECRET, this.clientSecret));

		HttpUriRequest request = RequestBuilder.create("POST").setUri(this.tokenEndpoint)
				.setHeader(HttpHeaders.ACCEPT, JSON_CONTENT_TYPE).setHeader(HttpHeaders.CONTENT_TYPE, FORM_CONTENT_TYPE)
				.setEntity(new UrlEncodedFormEntity(params)).build();

		HttpResponse response = this.httpClient.execute(request);

		if (response.getStatusLine().getStatusCode() == STATUS_SUCCESS) {
			JsonNode data = jsonParser.readTree(EntityUtils.toString(response.getEntity()));
			this.accessToken = data.get(FIELD_ACCESS_TOKEN).asText();
		} else {
			throw new HttpResponseException(response.getStatusLine().getStatusCode(), buildError(response));
		}

		this.doTokenValidate(true);
	}
}
