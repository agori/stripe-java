package com.stripe.model;

import com.stripe.exception.SignatureVerificationException;

import com.stripe.BaseStripeTest;
import com.stripe.model.Event;
import com.stripe.model.Webhook;

import com.google.gson.JsonSyntaxException;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.junit.Assert.assertEquals;

public class WebhookTest extends BaseStripeTest {
	public static String secret = null;
	public static String payload = null;

	@Before
	public void setUpFixtures() throws IOException {
		secret = "secret";
		payload = resource("account_event.json");
	}

	public String generateSigHeader() throws NoSuchAlgorithmException, InvalidKeyException {
		Map<String, Object> options = new HashMap<String, Object>();
		return generateSigHeader(options);
	}

	public String generateSigHeader(Map<String, Object> options) throws NoSuchAlgorithmException, InvalidKeyException {
		Long timestamp = (options.get("timestamp") != null) ? (Long)options.get("timestamp") : Webhook.Util.getTimeNow();
		String payload = (options.get("payload") != null) ? (String)options.get("payload") : this.payload;
		String secret = (options.get("secret") != null) ? (String)options.get("secret") : this.secret;
		String scheme = (options.get("scheme") != null) ? (String)options.get("scheme") : Webhook.EXPECTED_SCHEME;
		String signature = (String)options.get("signature");

		if (signature == null) {
			String payloadToSign = String.format("%d.%s", timestamp, payload);
			signature = Webhook.Util.computeHmacSHA256(secret, payloadToSign);
		}

		String header = String.format("t=%d,%s=%s", timestamp, scheme, signature);
		return header;
	}

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Test
	public void testValidJson() {
		Event event = Webhook.createEventFromPayload(payload);

		assertEquals("evt_00000000000000", event.getId());
		assertEquals("account.updated", event.getType());
	}

	@Test(expected=JsonSyntaxException.class)
	public void testInvalidJson() {
		String payload = "this is not valid JSON";
		Webhook.createEventFromPayload(payload);
	}

	@Test
	public void testValidJsonAndHeader() throws SignatureVerificationException, NoSuchAlgorithmException, InvalidKeyException {
		String sigHeader = generateSigHeader();

		Event event = Webhook.createEventFromPayload(payload, sigHeader, secret);

		assertEquals("evt_00000000000000", event.getId());
		assertEquals("account.updated", event.getType());
	}

	@Test(expected=SignatureVerificationException.class)
	public void testValidJsonAndInvalidHeader() throws SignatureVerificationException {
		String sigHeader = "bad_header";

		Webhook.createEventFromPayload(payload, sigHeader, secret);
	}

	@Test
	public void testMalformedHeader() throws SignatureVerificationException {
		String sigHeader = "i'm not even a real signature header";

		thrown.expect(SignatureVerificationException.class);
		thrown.expectMessage("Unable to extract timestamp and signatures from header");

		Webhook.verifyHeader(payload, sigHeader, secret);
	}

	@Test
	public void testNoSignaturesWithExpectedScheme() throws SignatureVerificationException, NoSuchAlgorithmException, InvalidKeyException {
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("scheme", "v0");
		String sigHeader = generateSigHeader(options);

		thrown.expect(SignatureVerificationException.class);
		thrown.expectMessage("No signatures found with expected scheme");

		Webhook.verifyHeader(payload, sigHeader, secret);
	}

	@Test
	public void testNoValidSignatureForPayload() throws SignatureVerificationException, NoSuchAlgorithmException, InvalidKeyException {
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("signature", "bad_signature");
		String sigHeader = generateSigHeader(options);

		thrown.expect(SignatureVerificationException.class);
		thrown.expectMessage("No signatures found matching the expected signature for payload");

		Webhook.verifyHeader(payload, sigHeader, secret);
	}

	@Test
	public void testTimestampOutsideTolerance() throws SignatureVerificationException, NoSuchAlgorithmException, InvalidKeyException {
		Map<String, Object> options = new HashMap<String, Object>();
		options.put("timestamp", Webhook.Util.getTimeNow() - 15);
		String sigHeader = generateSigHeader(options);

		thrown.expect(SignatureVerificationException.class);
		thrown.expectMessage("Timestamp outside the tolerance zone");

		Long tolerance = Long.valueOf(10);
		Webhook.verifyHeader(payload, sigHeader, secret, tolerance);
	}
}
